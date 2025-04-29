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
- Uses GitHub's search API for efficient scanning
- Configurable search patterns

## Installation

1. Make sure you have Go 1.21 or later installed
2. Clone this repository
3. Install dependencies:
   ```bash
   go mod download
   ```

## Usage

1. Create a GitHub Personal Access Token with `repo` scope
2. Set the token as an environment variable or use the command line flag:
   ```bash
   # Using environment variable
   export GITHUB_TOKEN=your_token_here
   
   # Using command line flag
   go run main.go -token your_token_here -query "your search query"
   ```

### Example

To search for potential API keys in Python files:
```bash
go run main.go -query "filename:*.py"
```

## Security Note

This tool is intended for security research and educational purposes only. Please use responsibly and respect GitHub's terms of service.
