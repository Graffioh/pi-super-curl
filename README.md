# pi-super-curl

A [pi coding agent](https://github.com/badlogic/pi-mono/) extension for API testing with an interactive TUI. Define your endpoints once, test them with `/scurl`.

https://github.com/user-attachments/assets/612542b1-5fd0-4cd5-a02e-9384cab9cc98

> ⚠️ Work in progress

## Install

```bash
pi install npm:pi-super-curl
```

The extension auto-creates symlinks for the `send-request` skill and `api-tester` agent.

<details>
<summary>Manual setup (if auto-setup fails)</summary>

```bash
EXT_DIR=$(find -L ~/.pi -path "*/pi-super-curl/skills" -type d 2>/dev/null | head -1 | sed 's|/skills||')
ln -s "$EXT_DIR/skills/send-request" ~/.pi/agent/skills/send-request
ln -s "$EXT_DIR/agents/api-tester.md" ~/.pi/agent/agents/api-tester.md
```
</details>

## Quick Start

1. Create `.pi-super-curl/config.json` in your project:

```json
{
  "baseUrl": "$API_BASE_URL",
  "envFile": ".env",
  "auth": {
    "type": "bearer",
    "token": "$API_TOKEN"
  },
  "endpoints": [
    { "name": "get-users", "url": "/users", "method": "GET" },
    { "name": "create-user", "url": "/users", "method": "POST" }
  ]
}
```

2. Create a `.env` file with your secrets:

```bash
API_BASE_URL=http://localhost:3000
API_TOKEN=your-token-here
```

3. Run `/scurl` and start testing!

## Commands

| Command | Description |
|---------|-------------|
| `/scurl` | Open the request builder |
| `/scurl-history` | Browse and replay recent requests |
| `/scurl-log` | Capture logs after a request (requires `customLogging` config) |

### `/scurl` Keybindings

| Key | Action |
|-----|--------|
| **Tab** | Navigate fields |
| **↑↓** | Change options or scroll body |
| **Enter** | Send request |
| **Ctrl+T** | Switch Default/Template mode |
| **Ctrl+U** | Import from cURL command |

### `/scurl-history` Keybindings

| Key | Action |
|-----|--------|
| **↑↓** or **j/k** | Navigate |
| **Enter** | Replay request |
| **d** | Toggle details |
| **x** | Delete entry |
| **c** | Clear all |

## Configuration Reference

### Authentication Types

```json
// Bearer token
{ "auth": { "type": "bearer", "token": "$API_TOKEN" } }

// API key (custom header)
{ "auth": { "type": "api-key", "token": "$API_KEY", "header": "X-API-Key" } }

// Basic auth
{ "auth": { "type": "basic", "username": "$USER", "password": "$PASS" } }

// JWT (auto-generated per request)
{
  "auth": {
    "type": "jwt",
    "secret": "$JWT_SECRET",
    "expiresIn": 3600,
    "payload": { "user_id": "{{env.USER_ID}}", "role": "authenticated" }
  }
}
```

### Template Variables

Use these anywhere in URLs, headers, or body:

| Variable | Description |
|----------|-------------|
| `{{uuid}}` | Random UUID v4 |
| `{{uuidv7}}` | Time-ordered UUID v7 |
| `{{timestamp}}` | Unix timestamp (seconds) |
| `{{timestamp_ms}}` | Unix timestamp (ms) |
| `{{date}}` | ISO date string |
| `{{env.VAR}}` or `{{$VAR}}` | Environment variable |

> **Note:** Use `$VAR` syntax for top-level config fields (`baseUrl`, `auth.token`, `auth.secret`).  
> Use `{{env.VAR}}` syntax inside URLs, headers, body, and JWT payloads.

### Endpoints with Default Body

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

### Templates (Quick Forms)

Create reusable request templates with custom input fields:

```json
{
  "templates": [
    {
      "name": "quick-chat",
      "description": "Send a chat message",
      "endpoint": "chat",
      "fields": [
        { "name": "message", "label": "Your message", "path": "messages[0].content" }
      ]
    }
  ]
}
```

Press **Ctrl+T** in `/scurl` to switch to Template mode.

### Custom Logging

Capture server logs after requests for debugging:

```json
{
  "customLogging": {
    "enabled": true,
    "outputDir": "~/Desktop/api-logs",
    "logs": {
      "backend": "/tmp/server.log",
      "app": "logs/app.log"
    },
    "postScript": "process-logs.js" 
  }
}
```

Run `/scurl-log` after a request to save timestamped logs to `outputDir`.

### All Config Options

| Option | Description | Default |
|--------|-------------|---------|
| `baseUrl` | Base URL for relative paths | - |
| `timeout` | Request timeout (ms) | 30000 |
| `envFile` | Path to .env file | - |
| `auth` | Authentication config | - |
| `headers` | Default headers for all requests | - |
| `endpoints` | Named endpoint definitions | - |
| `templates` | Quick-access templates | - |
| `customLogging` | Log capture config | - |

See `example.pi-super-curl/config.json` for a complete example.

## License

MIT
