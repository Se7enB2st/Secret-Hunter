# Secret Hunter

A Go-based tool for scanning GitHub repositories for leaked API keys and security credentials.

## Features

- Scans GitHub repositories for common patterns of sensitive information
- Supports multiple types of credentials:
  - API Keys
  - Secret Keys
  - AWS Access Keys
  - AWS Secret Keys
  - Slack Tokens
  - GitHub Tokens
  - Private Keys
  - Database URLs
  - JWT Tokens
  - Email Passwords
- Uses GitHub's search API for efficient scanning
- Configurable search patterns
- Environment-based configuration
- Sensitive data redaction
- Rate limiting

## Installation

1. Make sure you have Go 1.21 or later installed
2. Clone this repository
3. Install dependencies:
   ```bash
   go mod download
   ```

## Configuration

The tool can be configured using environment variables or a `.env` file. Create a `.env` file in the project root with the following variables:

```bash
# GitHub API Configuration
GITHUB_TOKEN=your_github_token_here

# Rate Limiting
RATE_LIMIT=30

# Output Configuration
OUTPUT_FILE=findings.json

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json

# Security Settings
ENABLE_REDACTION=true
REDACTION_PATTERN=****
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| GITHUB_TOKEN | GitHub personal access token | (required) |
| RATE_LIMIT | Maximum requests per minute | 30 |
| OUTPUT_FILE | Output file for findings | findings.json |
| LOG_LEVEL | Logging level (debug, info, warn, error) | info |
| LOG_FORMAT | Log format (json, text) | json |
| ENABLE_REDACTION | Enable redaction of sensitive data | true |
| REDACTION_PATTERN | Pattern to use for redaction | **** |
| HTTP_TIMEOUT | HTTP client timeout | 30s |

## Usage

1. Create a GitHub Personal Access Token with `repo` scope
2. Set up your `.env` file or environment variables
3. Run the tool:
   ```bash
   go run main.go -query "your search query"
   ```

### Example

To search for potential API keys in Python files:
```bash
go run main.go -query "filename:*.py"
```

## Security Notes

1. Never commit your `.env` file or any files containing sensitive information
2. The `.gitignore` file is configured to exclude sensitive files
3. Enable redaction in production environments
4. Use appropriate rate limiting to avoid API abuse
5. Review and validate findings before taking action

## License

MIT License
