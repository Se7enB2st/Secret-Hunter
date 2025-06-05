package main

import (
	"testing"
	"time"
)

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Normal string",
			input:    "test string",
			expected: "test string",
		},
		{
			name:     "String with control characters",
			input:    "test\x00string",
			expected: "teststring",
		},
		{
			name:     "String with special characters",
			input:    "test\nstring\r",
			expected: "teststring",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeInput(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeInput() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestShouldSkipFile(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		size        int64
		extensions  []string
		maxSize     int64
		shouldSkip  bool
	}{
		{
			name:       "File too large",
			path:       "test.txt",
			size:       2 * 1024 * 1024, // 2MB
			extensions: []string{},
			maxSize:    1024 * 1024, // 1MB
			shouldSkip: true,
		},
		{
			name:       "File extension not in list",
			path:       "test.txt",
			size:       1024,
			extensions: []string{"py", "js"},
			maxSize:    1024 * 1024,
			shouldSkip: true,
		},
		{
			name:       "Valid file",
			path:       "test.py",
			size:       1024,
			extensions: []string{"py", "js"},
			maxSize:    1024 * 1024,
			shouldSkip: false,
		},
		{
			name:       "No extension restrictions",
			path:       "test.txt",
			size:       1024,
			extensions: []string{},
			maxSize:    1024 * 1024,
			shouldSkip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldSkipFile(tt.path, tt.size, tt.extensions, tt.maxSize)
			if result != tt.shouldSkip {
				t.Errorf("shouldSkipFile() = %v, want %v", result, tt.shouldSkip)
			}
		})
	}
}

func TestIsBinaryFile(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "Text content",
			content:  "This is a text file",
			expected: false,
		},
		{
			name:     "Binary content with null byte",
			content:  "This is a\x00binary file",
			expected: true,
		},
		{
			name:     "Empty content",
			content:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBinaryFile(tt.content)
			if result != tt.expected {
				t.Errorf("isBinaryFile() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRedactSensitiveData(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		redactionPattern string
		expected       string
	}{
		{
			name:           "API key redaction",
			input:          "api_key=1234567890abcdef",
			redactionPattern: "****",
			expected:       "api_key=****",
		},
		{
			name:           "Multiple matches",
			input:          "api_key=123456\nsecret_key=abcdef",
			redactionPattern: "****",
			expected:       "api_key=****\nsecret_key=****",
		},
		{
			name:           "No matches",
			input:          "regular text",
			redactionPattern: "****",
			expected:       "regular text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactSensitiveData(tt.input, tt.redactionPattern)
			if result != tt.expected {
				t.Errorf("redactSensitiveData() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestScanStats(t *testing.T) {
	stats := &ScanStats{
		TotalFiles:    100,
		ScannedFiles:  50,
		SkippedFiles:  10,
		FindingsCount: 5,
		StartTime:     time.Now(),
		EndTime:       time.Now().Add(time.Minute),
	}

	if stats.TotalFiles != 100 {
		t.Errorf("TotalFiles = %v, want %v", stats.TotalFiles, 100)
	}
	if stats.ScannedFiles != 50 {
		t.Errorf("ScannedFiles = %v, want %v", stats.ScannedFiles, 50)
	}
	if stats.SkippedFiles != 10 {
		t.Errorf("SkippedFiles = %v, want %v", stats.SkippedFiles, 10)
	}
	if stats.FindingsCount != 5 {
		t.Errorf("FindingsCount = %v, want %v", stats.FindingsCount, 5)
	}
} 