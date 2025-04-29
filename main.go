package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/google/go-github/v56/github"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var (
	githubToken string
	searchQuery string
	patterns    = map[string]*regexp.Regexp{
		"API Key":        regexp.MustCompile(`(?i)(api[_-]?key|apikey)[\s:=]+['"]?([a-zA-Z0-9_-]{32,})['"]?`),
		"Secret Key":     regexp.MustCompile(`(?i)(secret[_-]?key|secretkey)[\s:=]+['"]?([a-zA-Z0-9_-]{32,})['"]?`),
		"AWS Access Key": regexp.MustCompile(`(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?access[_-]?key)[\s:=]+['"]?([A-Z0-9]{20})['"]?`),
		"AWS Secret Key": regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)[\s:=]+['"]?([A-Za-z0-9/+=]{40})['"]?`),
		"Slack Token":    regexp.MustCompile(`(?i)(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`),
		"GitHub Token":   regexp.MustCompile(`(?i)(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{82})`),
	}
)

func init() {
	flag.StringVar(&githubToken, "token", "", "GitHub personal access token")
	flag.StringVar(&searchQuery, "query", "", "Search query for GitHub repositories")
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
}

func main() {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	// Search repositories
	opts := &github.SearchOptions{
		Sort:  "updated",
		Order: "desc",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	results, _, err := client.Search.Code(ctx, searchQuery, opts)
	if err != nil {
		logrus.Fatalf("Error searching GitHub: %v", err)
	}

	logrus.Infof("Found %d results", results.GetTotal())

	for _, result := range results.CodeResults {
		repo := result.GetRepository()
		path := result.GetPath()
		htmlURL := result.GetHTMLURL()

		// Get file content
		content, _, _, err := client.Repositories.GetContents(ctx, repo.GetOwner().GetLogin(), repo.GetName(), path, nil)
		if err != nil {
			logrus.Errorf("Error getting content for %s: %v", htmlURL, err)
			continue
		}

		decodedContent, err := content.GetContent()
		if err != nil {
			logrus.Errorf("Error decoding content for %s: %v", htmlURL, err)
			continue
		}

		// Check for sensitive information
		for patternName, pattern := range patterns {
			matches := pattern.FindAllStringSubmatch(decodedContent, -1)
			if len(matches) > 0 {
				for _, match := range matches {
					if len(match) > 1 {
						logrus.Warnf("Found potential %s in %s", patternName, htmlURL)
						logrus.Warnf("Match: %s", strings.TrimSpace(match[0]))
					}
				}
			}
		}
	}
} 