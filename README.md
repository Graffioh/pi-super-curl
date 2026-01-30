# pi-super-curl

A [pi coding agent](https://github.com/badlogic/pi-mono/) extension for sending HTTP requests with an interactive TUI request builder. Define your API once, test it with `/scurl` by using your coding agent capabilities.

https://github.com/user-attachments/assets/612542b1-5fd0-4cd5-a02e-9384cab9cc98

Still work in progress.

## Why

API testing during development is repetitive. You're constantly:
- Copying auth tokens between tools
- Regenerating expired JWTs
- Retyping the same endpoints
- Coding agent don't have request <-> response context if called externally

pi super curl gives you a Postman-like request builder right in your coding agent:

```
/scurl
```

## Install

```bash
pi install npm:pi-super-curl
```

## Quick Start

1. Create `.super-curl.json`:

```json
{
  "baseUrl": "https://api.example.com",
  "auth": {
    "type": "bearer",
    "token": "$API_TOKEN"
  },
  "endpoints": [
    {
      "name": "...",
      "url": "...",
      "method": "..."
    }
  ]
}
```

2. Run `/scurl` to open the request builder

## Commands

### `/scurl`

Opens the interactive request builder UI. Build your request visually, then delegates execution to the `api-tester` subagent for a concise summary.

- **Ctrl+T** - Switch between Default and Template modes
- **Tab** - Navigate between fields
- **↑↓** - Change options (endpoints, methods) or scroll body content
- **Enter** - Send request

## Configuration

### Named Endpoints

Define frequently-used endpoints:

```json
{
  "endpoints": [
    {
      "name": "chat",
      "url": "/v1/chat/completions",
      "method": "POST",
      "defaultBody": {
        "model": "gpt-4",
        "temperature": 0.7
      }
    }
  ]
}
```

### Templates

Create quick-access templates with custom text fields so that you can reuse common API requests in a blink:

```json
{
  "templates": [
    {
      "name": "quick-chat",
      "description": "Send a chat message",
      "endpoint": "chat",
      "fields": [
        {
          "name": "message",
          "label": "Your message",
          "path": "messages[0].content"
        }
      ]
    }
  ]
}
```

Check `.super-curl.json` in this root project to understand a bit more how to structure a possible template.

### Authentication

**Bearer Token:**
```json
{ "auth": { "type": "bearer", "token": "$API_TOKEN" } }
```

**API Key:**
```json
{ "auth": { "type": "api-key", "token": "$API_KEY", "header": "X-API-Key" } }
```

**Basic Auth:**
```json
{ "auth": { "type": "basic", "username": "$USER", "password": "$PASS" } }
```

**JWT (auto-generated per request):**
```json
{
  "auth": {
    "type": "jwt",
    "secret": "$JWT_SECRET",
    "expiresIn": 3600,
    "payload": {
      "user_id": "{{env.USER_ID}}",
      "role": "authenticated"
    }
  }
}
```

### Template Variables

Dynamic values in URLs, headers, and body:

| Template | Description |
|----------|-------------|
| `{{uuid}}` | Random UUID v4 |
| `{{uuidv7}}` | Time-ordered UUID v7 |
| `{{timestamp}}` | Unix timestamp (seconds) |
| `{{timestamp_ms}}` | Unix timestamp (ms) |
| `{{date}}` | ISO date string |
| `{{env.VAR}}` or `{{$VAR}}` | Environment variables |

### Environment File

```json
{
  "envFile": ".env"
}
```

### Full Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `baseUrl` | Base URL for relative paths | - |
| `timeout` | Request timeout in ms | 30000 |
| `outputDir` | Directory to save responses | cwd |
| `envFile` | Path to .env file | - |
| `auth` | Authentication config | - |
| `headers` | Default headers | - |
| `endpoints` | Named endpoint definitions | - |
| `templates` | Quick-access templates | - |

## License

MIT
