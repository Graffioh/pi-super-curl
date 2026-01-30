---
name: send-request
description: Send HTTP requests with automatic configuration and authentication. Use when testing APIs, webhooks, or any HTTP endpoint.
---

# Send Request Skill

Sends HTTP requests with:
- **Config-based**: baseUrl, auth, headers (from `.pi-super-curl/config.json`)
- **Named endpoints**: Quick access via `@endpoint-name`
- **Template variables**: `{{uuid}}`, `{{uuidv7}}`, `{{env.VAR}}`, `{{timestamp}}`
- **JWT auth**: Auto-generates tokens with configurable payload
- **Env resolution**: `$VAR` syntax for secrets in config

## Usage

Run the `send-request.cjs` script with request parameters:

```bash
# First, find the script path
SCRIPT=$(find ~/.pi -path "*/pi-super-curl/skills/send-request/send-request.cjs" 2>/dev/null | head -1)

# Then use it
node "$SCRIPT" <METHOD> "<URL>" [options] 2>&1
```

**Parameters:**
- `METHOD`: GET, POST, PUT, PATCH, DELETE
- `URL`: Full URL or `@endpoint-name` from config
- `--body '{"key": "value"}'`: Request body (JSON, supports templates)
- `--header 'Name: Value'`: Custom header (repeatable)
- `--save`: Save response to `~/Desktop/api-responses/`
- `--stream`: Stream SSE responses

**Examples:**

```bash
# Simple GET request
node "$SCRIPT" GET "https://httpbin.org/get" 2>&1

# POST with JSON body and templates
node "$SCRIPT" POST "@chat" --body '{"id": "{{uuidv7}}", "user": "{{env.USER_ID}}"}' 2>&1

# Named endpoint from config
node "$SCRIPT" GET "@health" 2>&1

# With custom header
node "$SCRIPT" GET "https://api.example.com/data" --header "X-Custom: value" 2>&1
```

## Configuration

The script reads `.pi-super-curl/config.json` from the current directory (walking up) or home directory:

```json
{
  "baseUrl": "$API_BASE_URL",
  "envFile": ".env",
  "auth": {
    "type": "jwt",
    "secret": "$JWT_SECRET",
    "algorithm": "HS256",
    "expiresIn": 3600,
    "payload": {
      "user_id": "{{env.USER_ID}}",
      "role": "authenticated"
    }
  },
  "headers": {
    "Content-Type": "application/json",
    "X-Org-Id": "{{env.ORG_ID}}"
  },
  "endpoints": [
    {
      "name": "health",
      "url": "/health",
      "method": "GET"
    },
    {
      "name": "chat",
      "url": "/api/chat",
      "method": "POST",
      "defaultBody": {
        "chat_id": "{{uuidv7}}",
        "workspace_id": "{{env.WORKSPACE_ID}}"
      }
    }
  ]
}
```

## Template Variables

| Template | Description |
|----------|-------------|
| `{{uuid}}`, `{{uuidv4}}` | Random UUID v4 |
| `{{uuidv7}}` | Time-ordered UUID v7 |
| `{{timestamp}}` | Unix timestamp (seconds) |
| `{{timestamp_ms}}` | Unix timestamp (ms) |
| `{{date}}` | ISO date string |
| `{{env.VAR}}` or `{{$VAR}}` | Environment variables |

## Environment Resolution

Two syntaxes for different contexts:

| Syntax | Use in | Example |
|--------|--------|---------|
| `$VAR` | `baseUrl`, `auth.secret`, `auth.token` | `"baseUrl": "$API_URL"` |
| `{{env.VAR}}` | URLs, headers, body, JWT payload | `"user_id": "{{env.USER_ID}}"` |

## Authentication Types

### Bearer Token
```json
{"type": "bearer", "token": "$MY_API_TOKEN"}
```

### JWT (auto-generated)
```json
{
  "type": "jwt",
  "secret": "$JWT_SECRET",
  "algorithm": "HS256",
  "expiresIn": 3600,
  "payload": {
    "user_id": "{{env.USER_ID}}",
    "email": "{{env.EMAIL}}",
    "role": "authenticated"
  }
}
```

### API Key
```json
{"type": "api-key", "token": "$API_KEY", "header": "X-API-Key"}
```

### Basic Auth
```json
{"type": "basic", "username": "$USER", "password": "$PASS"}
```

## Output

The script outputs:
1. `[INFO]` lines to stderr (method, URL, timing)
2. Response body to stdout
3. Raw response saved to `/tmp/generation-output.txt` (for `/scurl-log`)
4. `[INFO] Request completed successfully` on success
5. `[ERROR]` on failure
