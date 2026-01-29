# Super Curl

A pi extension for sending HTTP requests with automatic configuration, authentication (including JWT generation), and response handling.

## Installation

```bash
# Load directly
pi -e ~/Desktop/super-curl

# Or symlink to extensions directory for auto-discovery
ln -s ~/Desktop/super-curl ~/.pi/agent/extensions/super-curl
```

## Quick Start

```bash
# Start pi with the extension
pi -e ~/Desktop/super-curl

# Ask the LLM to make requests
> Send a GET request to https://api.github.com/users/octocat

# Or use the /curl command
> /curl GET https://httpbin.org/get

# Use named endpoint with dynamic values
> /curl POST @chat --body '{"generation_params": {"positive_prompt": "a ninja"}}'
```

## Configuration

Create `.super-curl.json` in your project root or home directory:

```json
{
  "baseUrl": "https://api.example.com",
  "timeout": 30000,
  "outputDir": "~/Desktop/api-responses",
  "envFile": ".env.development",
  "auth": {
    "type": "bearer",
    "token": "$API_TOKEN"
  },
  "headers": {
    "X-Custom-Header": "value"
  },
  "endpoints": [
    {
      "name": "users",
      "url": "/v1/users",
      "method": "GET"
    }
  ]
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `baseUrl` | Base URL for relative paths | - |
| `timeout` | Request timeout in ms | 30000 |
| `outputDir` | Directory to save responses | cwd |
| `envFile` | Path to .env file to load | - |
| `auth` | Authentication config | - |
| `headers` | Default headers for all requests | - |
| `endpoints` | Named endpoint shortcuts | - |

## Environment File Loading

Load variables from a `.env` file:

```json
{
  "envFile": ".env.development"
}
```

Paths can be:
- Relative to project: `.env.development`
- Absolute: `/path/to/.env`
- Home-relative: `~/.env`

## Template Variables

Use template variables in URLs, headers, and body:

| Template | Description | Example |
|----------|-------------|---------|
| `{{uuid}}` or `{{uuidv4}}` | Random UUID v4 | `550e8400-e29b-41d4-a716-446655440000` |
| `{{uuidv7}}` | Time-ordered UUID v7 | `019abc12-3456-7890-abcd-ef1234567890` |
| `{{timestamp}}` | Unix timestamp (seconds) | `1706500000` |
| `{{timestamp_ms}}` | Unix timestamp (ms) | `1706500000123` |
| `{{date}}` | ISO date string | `2024-01-29T10:00:00.000Z` |
| `{{env.VAR}}` | Environment variable | Value of `$VAR` |
| `{{$VAR}}` | Environment variable | Value of `$VAR` |

### Example with Templates

```json
{
  "endpoints": [
    {
      "name": "chat",
      "url": "/v1/chat/messages",
      "method": "POST",
      "defaultBody": {
        "chat_id": "{{uuidv7}}",
        "workspace_id": "{{env.WORKSPACE_ID}}",
        "timestamp": "{{timestamp}}"
      }
    }
  ]
}
```

## Authentication Types

### Bearer Token
```json
{
  "auth": {
    "type": "bearer",
    "token": "$MY_API_TOKEN"
  }
}
```

Values starting with `$` are resolved from environment variables.

### API Key
```json
{
  "auth": {
    "type": "api-key",
    "token": "$API_KEY",
    "header": "X-API-Key"
  }
}
```

### Basic Auth
```json
{
  "auth": {
    "type": "basic",
    "username": "$USERNAME",
    "password": "$PASSWORD"
  }
}
```

### JWT Token (Dynamic Generation) 🆕

Generate fresh JWT tokens on every request:

```json
{
  "auth": {
    "type": "jwt",
    "secret": "$SUPABASE_JWT_SECRET",
    "algorithm": "HS256",
    "expiresIn": 3600,
    "payload": {
      "user_id": "{{env.USER_ID}}",
      "email": "{{env.EMAIL}}",
      "org_ids": ["{{env.ORG_ID}}"],
      "sub": "{{env.USER_ID}}",
      "role": "authenticated"
    }
  }
}
```

**JWT Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `secret` | JWT signing secret (use `$ENV_VAR`) | Required |
| `algorithm` | Signing algorithm | `HS256` |
| `expiresIn` | Token expiry in seconds | `3600` |
| `payload` | JWT payload (supports templates) | `{}` |

The `iat` and `exp` claims are auto-generated if not in payload.

## SSE Streaming & Debug Support

For streaming APIs (like AI chat endpoints), enable SSE parsing:

```json
{
  "endpoints": [
    {
      "name": "chat",
      "url": "/api/chat/messages",
      "method": "POST",
      "stream": true,
      "debug": {
        "workflowLogs": "apps/server/.next/dev/logs/next-development.log",
        "backendLogs": "/tmp/backend-output.txt"
      }
    }
  ]
}
```

When `stream: true`:
- Parses SSE `data:` events
- Extracts `text-delta` (agent responses)
- Captures `tool-output-available` (generated files)
- Detects errors and tool calls
- On failure, reads and includes debug logs

### Output Format (Streaming)

```
✓ 200 OK (5234ms)

✅ Generated 1 output(s):
  • image/png (1024x1024)
    ID: 019abc12-3456-7890-abcd-ef1234567890
    GCS: gs://bucket/path/to/output.png

📝 Agent response:
I've generated an image of a cyberpunk ninja...
```

### Debug Output (On Error)

```
=== DEBUG INFO ===

📛 Errors from response:
  - Generation failed: timeout

🔧 Tool calls made:
  - text_to_image_generation

📁 Log files to check:
  - Workflow logs: /path/to/workflow.log

--- Last workflow logs ---
[2024-01-29 10:00:00] Error: ComfyUI connection refused
...
--- End workflow logs ---
```

## Morphic Platform Example

For the Morphic platform-backend, copy `morphic.super-curl.json` to your project:

```bash
cp morphic.super-curl.json ~/Desktop/morphic/platform-backend/.super-curl.json
```

Then use:
```bash
# Generate an image
/curl @chat --body '{"generation_params": {"positive_prompt": "a cyberpunk ninja"}}'

# Generate a video  
/curl @chat-video --body '{"generation_params": {"positive_prompt": "a dancing robot"}}'

# Text/copilot mode
/curl @chat-text --body '{"content": "list files in docs/"}'
```

**On success**: Shows generated outputs with GCS URLs and inference request IDs
**On failure**: Automatically includes last 50 lines from workflow logs for debugging

Required `.env.development` variables:
```env
SUPABASE_JWT_SECRET=your-jwt-secret
MORPHIC_WORKSPACE_ID=your-workspace-id
MORPHIC_FILE_ID=your-file-id
MORPHIC_ORG_ID=your-org-id
MORPHIC_USER_ID=your-user-id
MORPHIC_EMAIL=your-email@example.com
```

## Tool: send_request

The LLM can use the `send_request` tool to make HTTP requests.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `method` | string | HTTP method: GET, POST, PUT, PATCH, DELETE |
| `url` | string | Full URL, path (with baseUrl), or @endpoint |
| `headers` | object | Additional headers |
| `body` | string | Request body (JSON string) |
| `save` | boolean | Save response to output directory |

### Examples

```
# Simple GET
Use send_request to GET https://api.github.com/users/octocat

# POST with body
Use send_request to POST /api/users with body {"name": "John"}

# Named endpoint
Use send_request to call @users endpoint

# Save response
Use send_request to GET /api/data and save the response

# With dynamic chat_id (auto-generated)
Use send_request to POST @chat with body {"generation_params": {"positive_prompt": "a sunset"}}
```

## Commands

### /request

Open the interactive Postman-like request builder UI:
```
/request
```

### /curl

Quick HTTP request from the command line:

```
/curl GET https://httpbin.org/get
/curl POST @chat --body '{"prompt": "hello"}'
```

### /endpoints

List configured endpoints:

```
/endpoints
```

## Named Endpoints

Define frequently-used endpoints in your config:

```json
{
  "endpoints": [
    {
      "name": "health",
      "url": "/health",
      "method": "GET"
    },
    {
      "name": "create-item",
      "url": "/items",
      "method": "POST",
      "defaultBody": {
        "id": "{{uuidv7}}",
        "created_at": "{{date}}"
      }
    }
  ]
}
```

Then use them:
```
/curl @health
/curl @create-item --body '{"name": "Widget"}'
```

Body provided via `--body` is merged with `defaultBody` (your values override defaults).

## Response Handling

- **Truncation**: Large responses are truncated to 10KB for LLM context
- **Saving**: Use `save: true` to save full response to output directory
- **JSON formatting**: JSON responses are automatically pretty-printed

## Output Directory

When `save: true` is set, responses are saved to:
- The `outputDir` from config (supports `~` for home directory)
- Or `~/Desktop/api-responses` if not configured

Files are named: `response_<timestamp>_<path>.<extension>`

## Philosophy

This extension is designed for:
- **Configuration over repetition**: Define auth and headers once
- **Dynamic tokens**: Generate fresh JWT tokens per request
- **Named endpoints**: Quick access to frequently-used APIs
- **Template variables**: Dynamic values without code changes
- **LLM-friendly**: Truncation and formatting for context efficiency
