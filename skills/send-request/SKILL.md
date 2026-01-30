---
name: send-request
description: Send HTTP requests with automatic configuration and authentication. Use when testing APIs, webhooks, or any HTTP endpoint.
---

# Send Request Skill

Sends HTTP requests with:
- **From config**: baseUrl, auth, headers (loaded from `.pi-super-curl/config.json`)
- **Named endpoints**: Quick access via `@endpoint-name`
- **Response saving**: Optional save to `~/Desktop/api-responses/`

## Usage

When invoked via the `/skill:send-request` command, the user provides the request details in the arguments.

**IMPORTANT**: Use EXACTLY the request details provided by the user. Do NOT modify the URL, method, or body unless explicitly asked.

## Execution

Run the `send-request.js` script with the request parameters:

```bash
node <skill-dir>/send-request.js <METHOD> "<URL>" [options] 2>&1
```

**Parameters:**
- `METHOD`: GET, POST, PUT, PATCH, DELETE
- `URL`: Full URL or `@endpoint-name` from config
- `--body '{"key": "value"}'`: Request body (JSON)
- `--header 'Name: Value'`: Custom header (repeatable)
- `--save`: Save response to `~/Desktop/api-responses/`

**Examples:**

```bash
# Simple GET request
node <skill-dir>/send-request.js GET "https://httpbin.org/get" 2>&1

# POST with JSON body
node <skill-dir>/send-request.js POST "https://httpbin.org/post" --body '{"name": "test", "value": 123}' 2>&1

# Named endpoint from config
node <skill-dir>/send-request.js GET "@health" 2>&1

# With custom header
node <skill-dir>/send-request.js GET "https://api.example.com/data" --header "X-Custom: value" 2>&1

# Save response to file
node <skill-dir>/send-request.js GET "https://api.example.com/large" --save 2>&1
```

## Configuration

The script reads `.pi-super-curl/config.json` from the current directory or parent directories:

```json
{
  "baseUrl": "https://api.example.com",
  "auth": {
    "type": "bearer",
    "token": "$API_TOKEN"
  },
  "headers": {
    "X-Custom-Header": "value"
  },
  "endpoints": [
    {
      "name": "health",
      "url": "/health",
      "method": "GET"
    },
    {
      "name": "users",
      "url": "/v1/users",
      "method": "POST",
      "defaultBody": {"role": "user"}
    }
  ]
}
```

Values starting with `$` are resolved from environment variables.

## Authentication Types

### Bearer Token
```json
{"type": "bearer", "token": "$MY_API_TOKEN"}
```

### API Key
```json
{"type": "api-key", "token": "$API_KEY", "header": "X-API-Key"}
```

### Basic Auth
```json
{"type": "basic", "username": "$USER", "password": "$PASS"}
```

## Output Format

The script outputs:
1. `[INFO]` lines to stderr (method, URL, timing)
2. Response body to stdout
3. `[INFO] Request completed successfully` on success
4. `[ERROR]` on failure

## Output Directory

When `--save` is used, responses are saved to:
```
~/Desktop/api-responses/response_<timestamp>_<path>.<ext>
```

## Troubleshooting

- **Connection refused**: Check the URL and that the server is running
- **401 Unauthorized**: Check auth config in `.pi-super-curl/config.json`
- **Endpoint not found**: Run with `@name` requires config with matching endpoint
- **Timeout**: Default is 30 seconds, server may be slow
