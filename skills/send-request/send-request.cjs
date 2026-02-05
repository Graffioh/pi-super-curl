#!/usr/bin/env node
/**
 * Send HTTP Request Script for pi-super-curl
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
 * Features:
 *   - Template variables: {{uuid}}, {{uuidv7}}, {{timestamp}}, {{env.VAR}}, {{$VAR}}
 *   - Environment resolution: $VAR in baseUrl, auth.secret, auth.token
 *   - JWT auth: auto-generates tokens with configurable payload
 *   - Named endpoints: @endpoint-name from config
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
const crypto = require('crypto');

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
        
        const cfg = JSON.parse(content);
        
        // Load envFile if specified
        if (cfg.envFile) {
          const configDir = path.dirname(path.dirname(configFile)); // Go up from .pi-super-curl/
          let envPath = cfg.envFile;
          if (!path.isAbsolute(envPath)) {
            if (envPath.startsWith('~')) {
              envPath = path.join(os.homedir(), envPath.slice(1));
            } else {
              envPath = path.join(configDir, envPath);
            }
          }
          if (fs.existsSync(envPath)) {
            loadEnvFile(envPath);
          }
        }
        
        return cfg;
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

// Generate UUIDv4
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Generate UUIDv7 (timestamp-based UUID)
function generateUUIDv7() {
  const timestamp = Date.now();
  const timestampHex = timestamp.toString(16).padStart(12, '0');
  const randomBytes = () => Math.floor(Math.random() * 16).toString(16);
  const randomHex = (len) => Array.from({ length: len }, randomBytes).join('');
  
  // UUIDv7 format: tttttttt-tttt-7xxx-yxxx-xxxxxxxxxxxx
  const uuid = [
    timestampHex.slice(0, 8),
    timestampHex.slice(8, 12),
    '7' + randomHex(3),
    ((parseInt(randomHex(1), 16) & 0x3) | 0x8).toString(16) + randomHex(3),
    randomHex(12)
  ].join('-');
  
  return uuid;
}

// Resolve environment variables (values starting with $)
function resolveEnvValue(value) {
  if (!value) return undefined;
  if (typeof value === 'string' && value.startsWith('$')) {
    return process.env[value.slice(1)];
  }
  return value;
}

// Process templates in a string: {{env.VAR}}, {{uuidv7}}, etc.
function processTemplates(str) {
  if (typeof str !== 'string') return str;
  
  return str.replace(/\{\{([^}]+)\}\}/g, (match, expr) => {
    const trimmed = expr.trim();
    
    // {{uuid}} or {{uuidv4}} - random UUID v4
    if (trimmed === 'uuid' || trimmed === 'uuidv4') {
      return generateUUID();
    }
    
    // {{uuidv7}} - time-ordered UUID v7
    if (trimmed === 'uuidv7') {
      return generateUUIDv7();
    }
    
    // {{timestamp}} - Unix timestamp in seconds
    if (trimmed === 'timestamp') {
      return Math.floor(Date.now() / 1000).toString();
    }
    
    // {{timestamp_ms}} - Unix timestamp in milliseconds
    if (trimmed === 'timestamp_ms') {
      return Date.now().toString();
    }
    
    // {{date}} - ISO date string
    if (trimmed === 'date') {
      return new Date().toISOString();
    }
    
    // {{env.VAR_NAME}} - environment variable
    if (trimmed.startsWith('env.')) {
      const varName = trimmed.slice(4);
      return process.env[varName] || match;
    }
    
    // {{$VAR_NAME}} - also support this format
    if (trimmed.startsWith('$')) {
      const varName = trimmed.slice(1);
      return process.env[varName] || match;
    }
    
    return match;
  });
}

// Recursively process templates in an object/array
function processTemplatesDeep(obj) {
  if (typeof obj === 'string') {
    return processTemplates(obj);
  }
  if (Array.isArray(obj)) {
    return obj.map(processTemplatesDeep);
  }
  if (obj && typeof obj === 'object') {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = processTemplatesDeep(value);
    }
    return result;
  }
  return obj;
}

// Simple base64url encoding
function base64url(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Generate JWT token
function generateJWT(auth) {
  const secret = resolveEnvValue(auth.secret);
  if (!secret) {
    console.error('[WARN] JWT secret not found');
    return null;
  }

  const algorithm = auth.algorithm || 'HS256';
  const expiresIn = auth.expiresIn || 3600;
  const now = Math.floor(Date.now() / 1000);

  // Process templates in payload
  const payload = processTemplatesDeep(auth.payload || {});
  payload.iat = now;
  payload.exp = now + expiresIn;

  const header = { alg: algorithm, typ: 'JWT' };
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signatureInput = `${headerB64}.${payloadB64}`;

  let hmacAlg;
  if (algorithm === 'HS256') hmacAlg = 'sha256';
  else if (algorithm === 'HS384') hmacAlg = 'sha384';
  else if (algorithm === 'HS512') hmacAlg = 'sha512';
  else {
    console.error(`[WARN] Unsupported JWT algorithm: ${algorithm}`);
    return null;
  }

  const signature = crypto
    .createHmac(hmacAlg, secret)
    .update(signatureInput)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${signatureInput}.${signature}`;
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
    case 'jwt': {
      const token = generateJWT(auth);
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
  const { method, url, headers, body, stream, timeout } = options;

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

    // Set timeout (default 30s, configurable)
    const timeoutMs = timeout || 30000;
    req.setTimeout(timeoutMs, () => {
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

Template Variables (in body, headers, URLs):
  {{uuid}}, {{uuidv4}}         Random UUID v4
  {{uuidv7}}                   Time-ordered UUID v7
  {{timestamp}}                Unix timestamp (seconds)
  {{timestamp_ms}}             Unix timestamp (milliseconds)
  {{date}}                     ISO date string
  {{env.VAR}} or {{$VAR}}      Environment variable

Config Values (baseUrl, auth.secret, auth.token):
  $VAR                         Resolve from environment

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

  // Handle named endpoints (@name) - check both endpoints and templates
  if (url.startsWith('@')) {
    const endpointName = url.slice(1);
    // Check endpoints first, then templates
    endpoint = config.endpoints?.find(e => e.name === endpointName) 
            || config.templates?.find(e => e.name === endpointName);
    
    if (!endpoint) {
      const endpointNames = config.endpoints?.map(e => e.name) || [];
      const templateNames = config.templates?.map(e => e.name) || [];
      const available = [...endpointNames, ...templateNames].join(', ') || 'none';
      console.error(`[ERROR] Endpoint "@${endpointName}" not found. Available: ${available}`);
      process.exit(1);
    }

    url = endpoint.url;
    method = endpoint.method || method;
    finalHeaders = { ...finalHeaders, ...endpoint.headers };
    
    // Merge default body with provided body (support both 'defaultBody' and 'body')
    const templateBody = endpoint.defaultBody || endpoint.body;
    if (templateBody) {
      if (body) {
        try {
          const parsedBody = JSON.parse(body);
          // Deep merge: provided body overrides templateBody
          body = JSON.stringify(deepMerge(templateBody, parsedBody));
        } catch {
          // Keep body as-is if not valid JSON
        }
      } else {
        body = JSON.stringify(templateBody);
      }
    }
  }

  // Build full URL with baseUrl
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    if (config.baseUrl) {
      // Resolve env vars in baseUrl (supports $VAR format)
      let resolvedBaseUrl = resolveEnvValue(config.baseUrl) || config.baseUrl;
      // Also process {{env.VAR}} templates
      resolvedBaseUrl = processTemplates(resolvedBaseUrl);
      url = `${resolvedBaseUrl.replace(/\/$/, '')}/${url.replace(/^\//, '')}`;
    } else {
      console.error('[ERROR] URL must be absolute or configure baseUrl in .pi-super-curl/config.json');
      process.exit(1);
    }
  }

  // Process templates in body
  if (body) {
    try {
      const parsedBody = JSON.parse(body);
      body = JSON.stringify(processTemplatesDeep(parsedBody));
    } catch {
      // If not JSON, process as string
      body = processTemplates(body);
    }
  }

  // Process templates in headers
  finalHeaders = processTemplatesDeep(finalHeaders);

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
      timeout: config.timeout,
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

    // Save raw output to /tmp for scurl-log
    try {
      fs.writeFileSync('/tmp/generation-output.txt', response.body);
    } catch {
      // Ignore
    }

    // Save if requested
    if (parsed.save) {
      const filepath = saveResponse(output, response.contentType, url);
      console.error(`[INFO] Saved to ${filepath}`);
    }

    // Handle customLogging if enabled
    if (config.customLogging?.enabled) {
      await processCustomLogging(config, response.body, parsed.configPath);
    }

    console.error('[INFO] Request completed successfully');
    process.exit(isSuccess ? 0 : 1);

  } catch (error) {
    console.error(`[ERROR] Request failed: ${error.message}`);
    process.exit(1);
  }
}

// Process custom logging - create output directory, copy logs, run postScript
async function processCustomLogging(config, responseBody, configPath) {
  const customLogging = config.customLogging;
  if (!customLogging) return;

  try {
    // Resolve output directory (expand ~)
    let outputDir = customLogging.outputDir || '~/Desktop/api-responses';
    if (outputDir.startsWith('~')) {
      outputDir = path.join(os.homedir(), outputDir.slice(1));
    }

    // Create timestamped subdirectory
    const timestamp = Date.now();
    const runDir = path.join(outputDir, String(timestamp));
    fs.mkdirSync(runDir, { recursive: true });

    console.error(`[INFO] CustomLogging: Created ${runDir}`);

    // Save backend response
    const backendLogPath = path.join(runDir, 'backend.txt');
    fs.writeFileSync(backendLogPath, responseBody);
    console.error(`[INFO] CustomLogging: Saved backend.txt`);

    // Copy workflow logs if specified
    if (customLogging.logs?.workflow) {
      let workflowLogPath = customLogging.logs.workflow;
      
      // Resolve relative paths from config directory
      if (!path.isAbsolute(workflowLogPath)) {
        // Find the config directory
        let configDir = process.cwd();
        if (configPath) {
          configDir = path.dirname(path.dirname(configPath));
        } else {
          // Walk up to find .pi-super-curl
          let dir = process.cwd();
          while (dir !== path.dirname(dir)) {
            if (fs.existsSync(path.join(dir, '.pi-super-curl', 'config.json'))) {
              configDir = dir;
              break;
            }
            dir = path.dirname(dir);
          }
        }
        workflowLogPath = path.join(configDir, workflowLogPath);
      }

      if (fs.existsSync(workflowLogPath)) {
        const workflowContent = fs.readFileSync(workflowLogPath, 'utf-8');
        fs.writeFileSync(path.join(runDir, 'workflow.txt'), workflowContent);
        console.error(`[INFO] CustomLogging: Copied workflow.txt`);
      } else {
        console.error(`[WARN] CustomLogging: Workflow log not found at ${workflowLogPath}`);
      }
    }

    // Run postScript if specified
    if (customLogging.postScript) {
      let postScriptPath = customLogging.postScript;
      
      // Resolve relative paths - postScript is relative to .pi-super-curl directory
      if (!path.isAbsolute(postScriptPath)) {
        let configDir = process.cwd();
        if (configPath) {
          configDir = path.dirname(configPath); // .pi-super-curl directory
        } else {
          // Walk up to find .pi-super-curl
          let dir = process.cwd();
          while (dir !== path.dirname(dir)) {
            const piSuperCurlDir = path.join(dir, '.pi-super-curl');
            if (fs.existsSync(path.join(piSuperCurlDir, 'config.json'))) {
              configDir = piSuperCurlDir;
              break;
            }
            dir = path.dirname(dir);
          }
        }
        postScriptPath = path.join(configDir, postScriptPath);
      }

      if (fs.existsSync(postScriptPath)) {
        console.error(`[INFO] CustomLogging: Running postScript ${postScriptPath}`);
        
        const { spawn } = require('child_process');
        
        // Determine how to run the script
        let cmd, args;
        if (postScriptPath.endsWith('.js') || postScriptPath.endsWith('.cjs')) {
          // Check shebang for bun
          const scriptContent = fs.readFileSync(postScriptPath, 'utf-8');
          if (scriptContent.startsWith('#!/usr/bin/env bun')) {
            cmd = 'bun';
          } else {
            cmd = 'node';
          }
          args = [postScriptPath, runDir];
        } else {
          cmd = postScriptPath;
          args = [runDir];
        }

        // Run asynchronously but wait for completion
        await new Promise((resolve, reject) => {
          const child = spawn(cmd, args, {
            stdio: ['pipe', 'pipe', 'pipe'],
            cwd: path.dirname(postScriptPath),
          });

          let stdout = '';
          let stderr = '';

          child.stdout.on('data', (data) => {
            stdout += data;
          });

          child.stderr.on('data', (data) => {
            stderr += data;
          });

          child.on('close', (code) => {
            if (stdout) {
              for (const line of stdout.trim().split('\n')) {
                console.error(`[PostScript] ${line}`);
              }
            }
            if (stderr) {
              for (const line of stderr.trim().split('\n')) {
                console.error(`[PostScript] ${line}`);
              }
            }
            
            if (code === 0 || code === 2) {
              // 0 = success, 2 = already processed (from process-generation.js)
              resolve();
            } else {
              console.error(`[WARN] CustomLogging: postScript exited with code ${code}`);
              resolve(); // Don't fail the main request
            }
          });

          child.on('error', (err) => {
            console.error(`[WARN] CustomLogging: postScript error: ${err.message}`);
            resolve(); // Don't fail the main request
          });
        });
      } else {
        console.error(`[WARN] CustomLogging: postScript not found at ${postScriptPath}`);
      }
    }
  } catch (error) {
    console.error(`[WARN] CustomLogging error: ${error.message}`);
    // Don't fail the main request
  }
}

// Deep merge objects (source overrides target)
function deepMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      if (target[key] && typeof target[key] === 'object' && !Array.isArray(target[key])) {
        result[key] = deepMerge(target[key], source[key]);
      } else {
        result[key] = source[key];
      }
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

main();
