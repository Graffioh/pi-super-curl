#!/usr/bin/env node
/**
 * Send HTTP Request Script
 * 
 * Usage: node send-request.js <method> <url> [options]
 * 
 * Options:
 *   --body '{"key": "value"}'    Request body (JSON)
 *   --header 'Name: Value'       Add header (repeatable)
 *   --save                       Save response to file
 *   --stream                     Stream SSE responses
 *   --config <path>              Config file path
 * 
 * Examples:
 *   node send-request.js GET https://api.example.com/users
 *   node send-request.js POST https://api.example.com/users --body '{"name": "John"}'
 *   node send-request.js GET @health   # Use named endpoint from config
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const http = require('http');

// Output directory for saved responses
const OUTPUT_DIR = path.join(os.homedir(), 'Desktop', 'api-responses');

// Parse command line arguments
function parseArgs(args) {
  const result = {
    method: 'GET',
    url: '',
    body: null,
    headers: {},
    save: false,
    stream: false,
    configPath: null,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    
    if (arg === '--body' && args[i + 1]) {
      result.body = args[++i];
    } else if (arg === '--header' && args[i + 1]) {
      const header = args[++i];
      const colonIndex = header.indexOf(':');
      if (colonIndex > 0) {
        const name = header.slice(0, colonIndex).trim();
        const value = header.slice(colonIndex + 1).trim();
        result.headers[name] = value;
      }
    } else if (arg === '--save') {
      result.save = true;
    } else if (arg === '--stream') {
      result.stream = true;
    } else if (arg === '--config' && args[i + 1]) {
      result.configPath = args[++i];
    } else if (!result.method || result.method === 'GET') {
      // First positional arg could be method or URL
      if (['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(arg.toUpperCase())) {
        result.method = arg.toUpperCase();
      } else if (!result.url) {
        result.url = arg;
      }
    } else if (!result.url) {
      result.url = arg;
    }
    i++;
  }

  return result;
}

// Find config file by walking up directories
function findConfigFile(startDir) {
  let dir = startDir;
  while (dir !== path.dirname(dir)) {
    const configPath = path.join(dir, '.pi-super-curl', 'config.json');
    if (fs.existsSync(configPath)) {
      return configPath;
    }
    dir = path.dirname(dir);
  }
  return null;
}

// Load configuration from .pi-super-curl/config.json
function loadConfig(configPath) {
  const paths = configPath 
    ? [configPath]
    : [
        findConfigFile(process.cwd()),
        path.join(os.homedir(), '.pi-super-curl', 'config.json'),
      ].filter(Boolean);

  for (const configFile of paths) {
    if (fs.existsSync(configFile)) {
      try {
        const content = fs.readFileSync(configFile, 'utf-8');
        console.error(`[INFO] Loaded config from ${configFile}`);
        
        // Also load .env file from same directory if exists
        const configDir = path.dirname(configFile);
        const envFile = path.join(path.dirname(configDir), '.env');
        if (fs.existsSync(envFile)) {
          loadEnvFile(envFile);
        }
        
        return JSON.parse(content);
      } catch (e) {
        console.error(`[WARN] Failed to parse ${configFile}: ${e.message}`);
      }
    }
  }

  return {};
}

// Load .env file
function loadEnvFile(envPath) {
  try {
    const content = fs.readFileSync(envPath, 'utf-8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const eqIndex = trimmed.indexOf('=');
        if (eqIndex > 0) {
          const key = trimmed.slice(0, eqIndex).trim();
          let value = trimmed.slice(eqIndex + 1).trim();
          // Remove quotes if present
          if ((value.startsWith('"') && value.endsWith('"')) ||
              (value.startsWith("'") && value.endsWith("'"))) {
            value = value.slice(1, -1);
          }
          if (!process.env[key]) {
            process.env[key] = value;
          }
        }
      }
    }
    console.error(`[INFO] Loaded env from ${envPath}`);
  } catch (e) {
    // Ignore errors
  }
}

// Resolve environment variables (values starting with $)
function resolveEnvValue(value) {
  if (!value) return undefined;
  if (value.startsWith('$')) {
    return process.env[value.slice(1)];
  }
  return value;
}

// Build auth header based on config
function buildAuthHeader(auth) {
  if (!auth || auth.type === 'none') return {};

  const headers = {};

  switch (auth.type) {
    case 'bearer': {
      const token = resolveEnvValue(auth.token);
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      break;
    }
    case 'api-key': {
      const token = resolveEnvValue(auth.token);
      const headerName = auth.header || 'X-API-Key';
      if (token) {
        headers[headerName] = token;
      }
      break;
    }
    case 'basic': {
      const username = resolveEnvValue(auth.username) || '';
      const password = resolveEnvValue(auth.password) || '';
      const encoded = Buffer.from(`${username}:${password}`).toString('base64');
      headers['Authorization'] = `Basic ${encoded}`;
      break;
    }
  }

  return headers;
}

// Save response to file
function saveResponse(response, contentType, url) {
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  const timestamp = Date.now();
  const urlPath = new URL(url).pathname.replace(/\//g, '_').slice(0, 50);

  let extension = 'txt';
  if (contentType?.includes('application/json')) {
    extension = 'json';
  } else if (contentType?.includes('text/html')) {
    extension = 'html';
  } else if (contentType?.includes('text/xml') || contentType?.includes('application/xml')) {
    extension = 'xml';
  }

  const filename = `response_${timestamp}${urlPath}.${extension}`;
  const filepath = path.join(OUTPUT_DIR, filename);
  fs.writeFileSync(filepath, response);
  
  return filepath;
}

// Make HTTP request
async function makeRequest(options) {
  const { method, url, headers, body, stream } = options;

  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const requestOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      headers: {
        'User-Agent': 'pi-super-curl/1.0',
        ...headers,
      },
    };

    if (body) {
      requestOptions.headers['Content-Type'] = requestOptions.headers['Content-Type'] || 'application/json';
      requestOptions.headers['Content-Length'] = Buffer.byteLength(body);
    }

    const startTime = Date.now();

    const req = client.request(requestOptions, (res) => {
      let data = '';
      const contentType = res.headers['content-type'];

      res.on('data', (chunk) => {
        data += chunk;
        if (stream) {
          process.stdout.write(chunk);
        }
      });

      res.on('end', () => {
        const duration = Date.now() - startTime;
        resolve({
          status: res.statusCode,
          statusText: res.statusMessage,
          headers: res.headers,
          contentType,
          body: data,
          duration,
        });
      });
    });

    req.on('error', (e) => {
      reject(e);
    });

    // Set timeout
    req.setTimeout(30000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    if (body) {
      req.write(body);
    }

    req.end();
  });
}

// Main function
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: node send-request.js <method> <url> [options]

Options:
  --body '{"key": "value"}'    Request body (JSON)
  --header 'Name: Value'       Add header (repeatable)
  --save                       Save response to file
  --stream                     Stream SSE responses
  --config <path>              Config file path

Examples:
  node send-request.js GET https://httpbin.org/get
  node send-request.js POST https://httpbin.org/post --body '{"name": "test"}'
  node send-request.js GET @health   # Use named endpoint from config
`);
    process.exit(0);
  }

  const parsed = parseArgs(args);
  const config = loadConfig(parsed.configPath);

  let url = parsed.url;
  let method = parsed.method;
  let finalHeaders = { ...config.headers, ...parsed.headers };
  let body = parsed.body;
  let endpoint = null;

  // Handle named endpoints (@name)
  if (url.startsWith('@')) {
    const endpointName = url.slice(1);
    endpoint = config.endpoints?.find(e => e.name === endpointName);
    
    if (!endpoint) {
      const available = config.endpoints?.map(e => e.name).join(', ') || 'none';
      console.error(`[ERROR] Endpoint "@${endpointName}" not found. Available: ${available}`);
      process.exit(1);
    }

    url = endpoint.url;
    method = endpoint.method || method;
    finalHeaders = { ...finalHeaders, ...endpoint.headers };
    
    // Merge default body with provided body
    if (endpoint.defaultBody) {
      if (body) {
        try {
          const parsedBody = JSON.parse(body);
          body = JSON.stringify({ ...endpoint.defaultBody, ...parsedBody });
        } catch {
          // Keep body as-is
        }
      } else {
        body = JSON.stringify(endpoint.defaultBody);
      }
    }
  }

  // Build full URL with baseUrl
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    if (config.baseUrl) {
      url = `${config.baseUrl.replace(/\/$/, '')}/${url.replace(/^\//, '')}`;
    } else {
      console.error('[ERROR] URL must be absolute or configure baseUrl in .pi-super-curl/config.json');
      process.exit(1);
    }
  }

  // Add auth headers
  const auth = endpoint?.auth || config.auth;
  if (auth) {
    Object.assign(finalHeaders, buildAuthHeader(auth));
  }

  console.error(`[INFO] ${method} ${url}`);
  if (body) {
    console.error(`[INFO] Body: ${body.slice(0, 100)}${body.length > 100 ? '...' : ''}`);
  }

  try {
    const response = await makeRequest({
      method,
      url,
      headers: finalHeaders,
      body,
      stream: parsed.stream,
    });

    const isSuccess = response.status >= 200 && response.status < 300;
    const icon = isSuccess ? '✓' : '✗';

    console.error(`\n[INFO] ${icon} ${response.status} ${response.statusText} (${response.duration}ms)`);

    // Format JSON responses
    let output = response.body;
    if (response.contentType?.includes('application/json')) {
      try {
        output = JSON.stringify(JSON.parse(response.body), null, 2);
      } catch {
        // Keep as-is
      }
    }

    // Print response (if not streaming, which already printed)
    if (!parsed.stream) {
      console.log(output);
    }

    // Save if requested
    if (parsed.save) {
      const filepath = saveResponse(output, response.contentType, url);
      console.error(`[INFO] Saved to ${filepath}`);
    }

    console.error('[INFO] Request completed successfully');
    process.exit(isSuccess ? 0 : 1);

  } catch (error) {
    console.error(`[ERROR] Request failed: ${error.message}`);
    process.exit(1);
  }
}

main();
