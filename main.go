package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/go-github/v56/github"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"github.com/secret-hunter/config"
)

var (
	searchQuery string
	patterns    = map[string]*regexp.Regexp{
		"API Key":        regexp.MustCompile(`(?i)(api[_-]?key|apikey)[\s:=]+['"]?([a-zA-Z0-9_-]{32,})['"]?`),
		"Secret Key":     regexp.MustCompile(`(?i)(secret[_-]?key|secretkey)[\s:=]+['"]?([a-zA-Z0-9_-]{32,})['"]?`),
		"AWS Access Key": regexp.MustCompile(`(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?access[_-]?key)[\s:=]+['"]?([A-Z0-9]{20})['"]?`),
		"AWS Secret Key": regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)[\s:=]+['"]?([A-Za-z0-9/+=]{40})['"]?`),
		"Slack Token":    regexp.MustCompile(`(?i)(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`),
		"GitHub Token":   regexp.MustCompile(`(?i)(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{82})`),
		"Private Key":    regexp.MustCompile(`(?i)-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`),
		"Database URL":   regexp.MustCompile(`(?i)(postgresql|mysql|mongodb)://[a-zA-Z0-9_-]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_-]+`),
		"JWT Token":      regexp.MustCompile(`(?i)eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.([a-zA-Z0-9_-]+)`),
		"Email Password": regexp.MustCompile(`(?i)(smtp|email)[\s:=]+['"]?([^'"]+)['"]?`),
	}
)

type SecurityFinding struct {
	Type        string
	URL         string
	Match       string
	Repository  string
	File        string
	LineNumber  int
	Context     string
	Timestamp   time.Time
}

type ScanStats struct {
	TotalFiles     int
	ScannedFiles   int
	SkippedFiles   int
	FindingsCount  int
	StartTime      time.Time
	EndTime        time.Time
}

func init() {
	flag.StringVar(&searchQuery, "query", "", "Search query for GitHub repositories")
	flag.Parse()

	if searchQuery == "" {
		logrus.Fatal("Search query is required. Set it via -query flag")
	}
}

func sanitizeInput(input string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, input)
}

func redactSensitiveData(input string, redactionPattern string) string {
	for _, pattern := range patterns {
		input = pattern.ReplaceAllString(input, redactionPattern)
	}
	return input
}

func shouldSkipFile(path string, size int64, extensions []string, maxSize int64) bool {
	// Skip if file is too large
	if size > maxSize {
		return true
	}

	// Skip if extensions are specified and file doesn't match
	if len(extensions) > 0 {
		ext := strings.ToLower(filepath.Ext(path))
		if ext == "" {
			return true
		}
		ext = ext[1:] // Remove the dot
		skip := true
		for _, allowed := range extensions {
			if ext == strings.ToLower(allowed) {
				skip = false
				break
			}
		}
		if skip {
			return true
		}
	}

	return false
}

func printProgress(stats *ScanStats) {
	if stats.TotalFiles == 0 {
		return
	}
	progress := float64(stats.ScannedFiles) / float64(stats.TotalFiles) * 100
	color.Cyan("\rProgress: %.1f%% (%d/%d files) | Findings: %d | Skipped: %d",
		progress, stats.ScannedFiles, stats.TotalFiles, stats.FindingsCount, stats.SkippedFiles)
}

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		color.Red("Error loading configuration: %v", err)
		os.Exit(1)
	}

	// Set up logging
	if cfg.LogFormat == "json" {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{})
	}
	
	logLevel, _ := logrus.ParseLevel(cfg.LogLevel)
	logrus.SetLevel(logLevel)
	logrus.SetOutput(os.Stdout)

	ctx := context.Background()
	
	// Set up rate limiting
	limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit/60.0), 1)
	
	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: cfg.HTTPTimeout,
	}
	
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: cfg.GitHubToken},
	)
	tc := oauth2.NewClient(ctx, ts)
	tc.Transport = &oauth2.Transport{
		Base:   httpClient.Transport,
		Source: ts,
	}
	
	client := github.NewClient(tc)

	// Search repositories
	opts := &github.SearchOptions{
		Sort:  "updated",
		Order: "desc",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	// Sanitize search query
	searchQuery = sanitizeInput(searchQuery)

	results, _, err := client.Search.Code(ctx, searchQuery, opts)
	if err != nil {
		color.Red("Error searching GitHub: %v", err)
		os.Exit(1)
	}

	stats := &ScanStats{
		TotalFiles: len(results.CodeResults),
		StartTime:  time.Now(),
	}

	color.Green("Found %d files to scan", stats.TotalFiles)

	var findings []SecurityFinding

	for _, result := range results.CodeResults {
		// Respect rate limit
		if err := limiter.Wait(ctx); err != nil {
			color.Yellow("Rate limit exceeded: %v", err)
			break
		}

		repo := result.GetRepository()
		path := result.GetPath()
		htmlURL := result.GetHTMLURL()

		// Get file content
		content, _, _, err := client.Repositories.GetContents(ctx, repo.GetOwner().GetLogin(), repo.GetName(), path, nil)
		if err != nil {
			color.Yellow("Error getting content for %s: %v", htmlURL, err)
			continue
		}

		// Skip if file doesn't meet criteria
		if shouldSkipFile(path, int64(content.GetSize()), cfg.FileExtensions, cfg.MaxFileSize) {
			stats.SkippedFiles++
			continue
		}

		decodedContent, err := content.GetContent()
		if err != nil {
			color.Yellow("Error decoding content for %s: %v", htmlURL, err)
			continue
		}

		stats.ScannedFiles++

		// Split content into lines for better context
		lines := strings.Split(decodedContent, "\n")

		// Check for sensitive information
		for patternName, pattern := range patterns {
			matches := pattern.FindAllStringSubmatch(decodedContent, -1)
			if len(matches) > 0 {
				for _, match := range matches {
					if len(match) > 1 {
						// Find line number and context
						lineNumber := 0
						context := ""
						for i, line := range lines {
							if strings.Contains(line, match[0]) {
								lineNumber = i + 1
								// Get 2 lines before and after for context
								start := max(0, i-2)
								end := min(len(lines), i+3)
								context = strings.Join(lines[start:end], "\n")
								break
							}
						}

						// Redact sensitive data if enabled
						matchText := match[0]
						if cfg.EnableRedaction {
							matchText = redactSensitiveData(matchText, cfg.RedactionPattern)
							context = redactSensitiveData(context, cfg.RedactionPattern)
						}

						finding := SecurityFinding{
							Type:       patternName,
							URL:        htmlURL,
							Match:      strings.TrimSpace(matchText),
							Repository: repo.GetFullName(),
							File:       path,
							LineNumber: lineNumber,
							Context:    context,
							Timestamp:  time.Now(),
						}

						findings = append(findings, finding)
						stats.FindingsCount++

						color.Yellow("Found potential %s in %s", patternName, htmlURL)
						color.White("Repository: %s", repo.GetFullName())
						color.White("File: %s", path)
						color.White("Line: %d", lineNumber)
						if context != "" {
							color.White("Context:\n%s", context)
						}
						color.White("---")
					}
				}
			}
		}

		// Show progress if enabled
		if cfg.ShowProgress {
			printProgress(stats)
		}
	}

	stats.EndTime = time.Now()

	// Print final statistics
	color.Green("\n\nScan completed in %v", stats.EndTime.Sub(stats.StartTime))
	color.White("Total files: %d", stats.TotalFiles)
	color.White("Scanned files: %d", stats.ScannedFiles)
	color.White("Skipped files: %d", stats.SkippedFiles)
	color.Yellow("Total findings: %d", stats.FindingsCount)

	// Save findings to file
	if err := saveFindings(findings, cfg.OutputFile, cfg.OutputFormat); err != nil {
		color.Red("Error saving findings: %v", err)
	} else {
		color.Green("Findings saved to %s", cfg.OutputFile)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func saveFindings(findings []SecurityFinding, outputFile string, format string) error {
	// Implement saving findings to file
	// This is a placeholder - you should implement proper JSON/text serialization
	// and file handling with appropriate error checking
	return nil
} 