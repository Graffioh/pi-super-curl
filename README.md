# pi-super-curl

A [pi coding agent](https://github.com/badlogic/pi-mono/) extension for API testing with an interactive TUI.

https://github.com/user-attachments/assets/612542b1-5fd0-4cd5-a02e-9384cab9cc98

## Two Modes

| Mode | Purpose |
|------|---------|
| **Default** | Simple Postman client — manually fill URL, method, headers, body |
| **Template** | Pre-configured requests — just fill a few input fields |

Press **Ctrl+T** to switch between modes.

## Install

```bash
pi install npm:pi-super-curl
```

## Quick Start

### 1. Create config file

Create `.pi-super-curl/config.json` in your project:

```json
{
  "defaults": {
    "baseUrl": "$API_BASE_URL",
    "envFile": ".env",
    "headers": {
      "Content-Type": "application/json"
    }
  },
  "templates": [
    {
      "name": "create-user",
      "description": "Create a new user",
      "url": "/api/users",
      "method": "POST",
      "auth": {
        "type": "bearer",
        "token": "$API_TOKEN"
      },
      "body": {
        "name": "",
        "email": ""
      },
      "fields": [
        { "name": "name", "label": "Name", "path": "name" },
        { "name": "email", "label": "Email", "path": "email" }
      ]
    }
  ]
}
```

### 2. Create `.env` file

```bash
API_BASE_URL=http://localhost:3000
API_TOKEN=your-token-here
```

### 3. Run `/scurl`

## Commands

| Command | Description |
|---------|-------------|
| `/scurl` | Open request builder |
| `/scurl-history` | Browse and replay past requests |
| `/scurl-log` | Capture logs after request (requires `customLogging`) |

### Keybindings

| Key | Action |
|-----|--------|
| **Tab** | Navigate fields |
| **↑↓** | Change selection / scroll |
| **Enter** | Send request |
| **Ctrl+T** | Switch Default/Template mode |
| **Ctrl+U** | Import from cURL command |
| **Esc** | Cancel |

## Configuration

### Structure Overview

```json
{
  "defaults": { ... },      // Settings for Default mode (simple Postman)
  "templates": [ ... ],     // Pre-configured requests for Template mode
  "customLogging": { ... }  // Optional: log capture for debugging
}
```

### `defaults` — Simple Postman Mode

Settings used when you manually build requests in Default mode:

```json
{
  "defaults": {
    "baseUrl": "$API_BASE_URL",
    "timeout": 30000,
    "envFile": ".env",
    "headers": {
      "Content-Type": "application/json"
    },
    "auth": {
      "type": "bearer",
      "token": "$API_TOKEN"
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `baseUrl` | Prepended to relative URLs |
| `timeout` | Request timeout in ms (default: 30000) |
| `envFile` | Path to `.env` file |
| `headers` | Default headers for all requests |
| `auth` | Default authentication |

### `templates` — Pre-configured Requests

Each template is **self-contained** with its own URL, auth, headers, etc:

```json
{
  "templates": [
    {
      "name": "get-user",
      "description": "Get user by ID",
      "baseUrl": "$API_BASE_URL",
      "url": "/api/users/{{env.USER_ID}}",
      "method": "GET",
      "auth": {
        "type": "bearer",
        "token": "$API_TOKEN"
      }
    },
    {
      "name": "create-post",
      "description": "Create a blog post",
      "url": "/api/posts",
      "method": "POST",
      "headers": {
        "X-Custom-Header": "value"
      },
      "body": {
        "title": "",
        "content": "",
        "author_id": "{{env.USER_ID}}"
      },
      "fields": [
        { "name": "title", "label": "Title", "path": "title" },
        { "name": "content", "label": "Content", "path": "content" }
      ]
    }
  ]
}
```

#### Template Fields

| Field | Description |
|-------|-------------|
| `name` | Template identifier |
| `description` | Shown in UI selector |
| `baseUrl` | Optional, overrides `defaults.baseUrl` |
| `url` | Endpoint path (supports template variables) |
| `method` | HTTP method (GET, POST, PUT, PATCH, DELETE) |
| `stream` | Enable SSE streaming |
| `auth` | Template-specific auth config |
| `headers` | Template-specific headers |
| `body` | Request body template |
| `fields` | User input fields |
| `appendField` | Auto-add "Additional Instructions" field |

#### Input Fields

Define what users fill in:

```json
{
  "fields": [
    {
      "name": "prompt",
      "label": "Your prompt",
      "path": "data.message",
      "hint": "→ data.message",
      "default": "Hello",
      "required": true
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `name` | Field identifier |
| `label` | Display label |
| `path` | JSON path where value is injected (e.g., `data.message`) |
| `hint` | Optional hint shown in UI |
| `default` | Default value |
| `required` | Whether field is required |
| `sendToAgent` | If true, value goes to pi agent instead of HTTP body |

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
    "algorithm": "HS256",
    "expiresIn": 3600,
    "payload": {
      "user_id": "{{env.USER_ID}}",
      "role": "authenticated"
    }
  }
}
```

### Template Variables

Use anywhere in URLs, headers, body:

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

Run `/scurl-log` after a request to save timestamped logs.

## Example: Full Config

```json
{
  "defaults": {
    "baseUrl": "$API_BASE_URL",
    "envFile": ".env",
    "timeout": 30000,
    "headers": {
      "Content-Type": "application/json"
    }
  },
  "templates": [
    {
      "name": "health-check",
      "description": "Check API health",
      "url": "/health",
      "method": "GET"
    },
    {
      "name": "login",
      "description": "Authenticate user",
      "url": "/api/auth/login",
      "method": "POST",
      "body": {
        "email": "",
        "password": ""
      },
      "fields": [
        { "name": "email", "label": "Email", "path": "email" },
        { "name": "password", "label": "Password", "path": "password" }
      ]
    },
    {
      "name": "create-item",
      "description": "Create new item",
      "url": "/api/items",
      "method": "POST",
      "auth": {
        "type": "bearer",
        "token": "$API_TOKEN"
      },
      "body": {
        "id": "{{uuidv7}}",
        "name": "",
        "created_at": "{{date}}"
      },
      "fields": [
        { "name": "name", "label": "Item name", "path": "name" }
      ]
    }
  ],
  "customLogging": {
    "enabled": true,
    "outputDir": "~/Desktop/api-logs",
    "logs": {
      "server": "/tmp/server.log"
    }
  }
}
```

## License

MIT
