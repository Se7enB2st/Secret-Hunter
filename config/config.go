package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

type Config struct {
	GitHubToken     string
	RateLimit       int
	OutputFile      string
	LogLevel        string
	LogFormat       string
	EnableRedaction bool
	RedactionPattern string
	HTTPTimeout     time.Duration
}

// LoadConfig loads configuration from environment variables and .env file
func LoadConfig() (*Config, error) {
	// Try to load .env file, but don't fail if it doesn't exist
	_ = godotenv.Load()

	config := &Config{
		GitHubToken:     getEnvOrDefault("GITHUB_TOKEN", ""),
		RateLimit:       getEnvIntOrDefault("RATE_LIMIT", 30),
		OutputFile:      getEnvOrDefault("OUTPUT_FILE", "findings.json"),
		LogLevel:        getEnvOrDefault("LOG_LEVEL", "info"),
		LogFormat:       getEnvOrDefault("LOG_FORMAT", "json"),
		EnableRedaction: getEnvBoolOrDefault("ENABLE_REDACTION", true),
		RedactionPattern: getEnvOrDefault("REDACTION_PATTERN", "****"),
		HTTPTimeout:     getEnvDurationOrDefault("HTTP_TIMEOUT", 30*time.Second),
	}

	// Validate required settings
	if config.GitHubToken == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN is required")
	}

	// Validate rate limit
	if config.RateLimit < 1 || config.RateLimit > 100 {
		return nil, fmt.Errorf("RATE_LIMIT must be between 1 and 100")
	}

	// Validate log level
	if _, err := logrus.ParseLevel(config.LogLevel); err != nil {
		return nil, fmt.Errorf("invalid LOG_LEVEL: %v", err)
	}

	return config, nil
}

// Helper functions for environment variables
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
} 