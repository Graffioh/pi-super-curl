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

1. Create `.pi-super-curl/` directory in your project:

```
your-project/
└── .pi-super-curl/
    ├── config.json          # Configuration
    └── my-script.js         # Custom post-processing scripts (optional)
```

2. Configure your endpoints in `config.json`:

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
- **Ctrl+U** - Import from cURL command (opens popup)
- **Tab** - Navigate between fields
- **↑↓** - Change options (endpoints, methods) or scroll body content
- **Enter** - Send request

#### cURL Import

Press **Ctrl+U** to open the import popup, paste a cURL command, and press **Ctrl+Enter** to parse and populate the form. Supports:

```bash
curl -X POST https://api.example.com/endpoint \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer token123' \
  -d '{"key": "value"}'
```

The parser handles:
- `-X` / `--request` for HTTP method
- `-H` / `--header` for headers
- `-d` / `--data` / `--data-raw` for request body
- `--json` shorthand
- Quoted strings and escaped characters
- Multi-line commands with `\` continuations

### `/scurl-history`

Browse and replay your recent requests. History is stored in `~/.super-curl-history.json` (last 50 requests).

- **↑↓** or **j/k** - Navigate through history
- **Enter** - Replay selected request
- **d** - Toggle details view (shows full body, headers)
- **x** or **Backspace** - Delete selected entry
- **c** - Clear all history
- **Esc** - Close

### `/scurl-log`

Capture logs after a request completes. Requires `customLogging` to be configured (see [Custom Logging](#custom-logging-project-specific)).

Creates a timestamped directory with all configured log files and optionally runs a post-processing script.

## Suggested Workflow

Once configured, pi-super-curl enables a powerful API request-debug workflow:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  /scurl  ──►  Send Request  ──►  Wait for Results  ──►  Ask Questions   │
│                                                                         │
│                                      │                                  │
│                                      ▼                                  │
│                                                                         │
│                              /scurl-log  ──►  Parse & Save Logs         │
│                                                                         │
│                                      │                                  │
│                                      ▼                                  │
│                                                                         │
│                        View in Custom Log Viewer (optional)             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

1. **`/scurl`** - Build and send complex API requests in seconds using the interactive TUI
2. **Wait for results** - The request executes via subagent, streaming response back to your session
3. **Analyze in context** - Results and logs are now in your pi session — ask whatever you want about them
4. **`/scurl-log`** - Parse logs from your services and save them to a timestamped output directory
5. **View logs** - Use your preferred log viewer to inspect the captured data

**Why this works:**

- Your coding agent has full context of the request and response
- No context-switching between external tools
- Logs are organized and timestamped automatically
- Post-processing scripts can transform raw logs into useful formats

**Setup checklist:**

1. Create `.pi-super-curl/config.json` with your endpoints and auth
2. Configure `customLogging` with paths to your service logs
3. (Optional) Add a `postScript` for custom log processing
4. (Optional) Build a log viewer for your specific needs

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

Check `example.pi-super-curl/config.json` in this project to see a full configuration example.

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

### Custom Logging (Project-Specific)

Capture logs after a request completes using `/scurl-log`. This is useful for debugging and keeping a history of API responses with associated log files.

```json
{
  "customLogging": {
    "enabled": true,
    "outputDir": "~/Desktop/api-generations",
    "logs": {
      "backend": "/tmp/generation-output.txt",
      "workflow": "apps/orcrust/.next/dev/logs/next-development.log"
    },
    "postScript": ".scripts/process-generation.js"
  }
}
```

**Workflow:**
1. Run `/scurl` to send request (via subagent)
2. Wait for request to complete
3. Run `/scurl-log` to capture logs

**Output Structure:**
```
~/Desktop/custom-output-logs/
└── 1706648123456/          # Unix timestamp
    ├── backend.txt         # Copied from logs.backend
    └── backend2.txt        # Copied from logs.backend2
```

**Configuration:**

| Field | Description |
|-------|-------------|
| `enabled` | Enable the `/scurl-log` command |
| `outputDir` | Directory to save outputs (supports `~`) |
| `logs` | Map of log names to file paths (copied as `<name>.txt`) |
| `postScript` | Optional script to run after logging (receives output dir as argument) |

The `logs` field is flexible - define any log files you need:
```json
{
  "logs": {
    "backend": "/tmp/server.log",
    "backend2": "logs/backend2.log",
    "debug": "/var/log/app-debug.log"
  }
}
```

**Post-Processing Script:**

For custom processing (e.g., parsing SSE responses, downloading from GCS), provide a `postScript`. Scripts are resolved relative to the config directory (`.pi-super-curl/`):

```
your-project/
└── .pi-super-curl/
    ├── config.json
    └── process-output.js    # Referenced as "process-output.js" in config
```

```json
{
  "customLogging": {
    "enabled": true,
    "outputDir": "~/Desktop/generations",
    "logs": { "backend": "/tmp/output.txt" },
    "postScript": "process-output.js"
  }
}
```

The script receives the output directory path as its first argument:
```javascript
#!/usr/bin/env bun
const outputDir = process.argv[2];
// Parse logs, download files, etc.
```

### Full Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `baseUrl` | Base URL for relative paths | - |
| `timeout` | Request timeout in ms | 30000 |
| `envFile` | Path to .env file | - |
| `auth` | Authentication config | - |
| `headers` | Default headers | - |
| `endpoints` | Named endpoint definitions | - |
| `templates` | Quick-access templates | - |
| `customLogging` | Project-specific logging (see below) | - |

## License

MIT
