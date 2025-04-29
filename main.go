package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v56/github"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

var (
	githubToken string
	searchQuery string
	rateLimit   int
	outputFile  string
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

func init() {
	flag.StringVar(&githubToken, "token", "", "GitHub personal access token")
	flag.StringVar(&searchQuery, "query", "", "Search query for GitHub repositories")
	flag.IntVar(&rateLimit, "rate", 30, "Maximum requests per minute")
	flag.StringVar(&outputFile, "output", "findings.json", "Output file for findings")
	flag.Parse()

	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
		if githubToken == "" {
			logrus.Fatal("GitHub token is required. Set it via -token flag or GITHUB_TOKEN environment variable")
		}
	}

	if searchQuery == "" {
		logrus.Fatal("Search query is required. Set it via -query flag")
	}

	// Validate rate limit
	if rateLimit < 1 || rateLimit > 100 {
		logrus.Fatal("Rate limit must be between 1 and 100 requests per minute")
	}

	// Set up logging
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
}

func sanitizeInput(input string) string {
	// Remove any potential command injection characters
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, input)
}

func main() {
	ctx := context.Background()
	
	// Set up rate limiting
	limiter := rate.NewLimiter(rate.Limit(rateLimit/60.0), 1)
	
	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
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
		logrus.WithError(err).Fatal("Error searching GitHub")
	}

	logrus.WithField("total_results", results.GetTotal()).Info("Search completed")

	var findings []SecurityFinding

	for _, result := range results.CodeResults {
		// Respect rate limit
		if err := limiter.Wait(ctx); err != nil {
			logrus.WithError(err).Error("Rate limit exceeded")
			break
		}

		repo := result.GetRepository()
		path := result.GetPath()
		htmlURL := result.GetHTMLURL()

		// Get file content
		content, _, _, err := client.Repositories.GetContents(ctx, repo.GetOwner().GetLogin(), repo.GetName(), path, nil)
		if err != nil {
			logrus.WithError(err).WithField("url", htmlURL).Error("Error getting content")
			continue
		}

		decodedContent, err := content.GetContent()
		if err != nil {
			logrus.WithError(err).WithField("url", htmlURL).Error("Error decoding content")
			continue
		}

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

						finding := SecurityFinding{
							Type:       patternName,
							URL:        htmlURL,
							Match:      strings.TrimSpace(match[0]),
							Repository: repo.GetFullName(),
							File:       path,
							LineNumber: lineNumber,
							Context:    context,
							Timestamp:  time.Now(),
						}

						findings = append(findings, finding)

						logrus.WithFields(logrus.Fields{
							"type":        patternName,
							"url":         htmlURL,
							"repository":  repo.GetFullName(),
							"file":        path,
							"line_number": lineNumber,
						}).Warn("Found potential security issue")
					}
				}
			}
		}
	}

	// Save findings to file
	if err := saveFindings(findings); err != nil {
		logrus.WithError(err).Error("Error saving findings")
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

func saveFindings(findings []SecurityFinding) error {
	// Implement saving findings to file
	// This is a placeholder - you should implement proper JSON serialization
	// and file handling with appropriate error checking
	return nil
} 