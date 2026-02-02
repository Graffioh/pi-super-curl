/**
 * Super Curl - HTTP Request Extension for Pi
 *
 * A Postman-like tool for sending HTTP requests with:
 * - Interactive UI popup for building requests
 * - Environment-based configuration
 * - Automatic authentication (Bearer tokens, API keys, JWT generation)
 * - Response saving to configurable directory
 * - Template variables ({{uuid}}, {{uuidv7}}, {{env.VAR}}, {{timestamp}})
 * - Request history with replay support
 * - cURL import (Ctrl+U in request builder)
 * - Custom logging with optional post-processing script
 *
 * Usage:
 *   pi -e ~/Desktop/super-curl
 *
 * Commands:
 *   /scurl - Open Postman-like request builder UI (Ctrl+U to import cURL)
 *   /scurl-history - Browse and replay past requests
 *   /scurl-log - Capture logs after request (uses customLogging config)
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type } from "@sinclair/typebox";
import { StringEnum } from "@mariozechner/pi-ai";
import { Text, Editor, type EditorTheme, Key, matchesKey } from "@mariozechner/pi-tui";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import jwt from "jsonwebtoken";
import { v4 as uuidv4, v7 as uuidv7 } from "uuid";
import dotenv from "dotenv";

// Configuration types
interface JwtAuthConfig {
	type: "jwt";
	secret: string; // Can be $ENV_VAR
	algorithm?: jwt.Algorithm;
	expiresIn?: number; // seconds, default 3600
	payload: Record<string, unknown>; // Values can be $ENV_VAR or {{template}}
}

interface AuthConfig {
	type: "bearer" | "api-key" | "basic" | "none" | "jwt";
	token?: string;
	header?: string;
	username?: string;
	password?: string;
	// JWT-specific fields
	secret?: string;
	algorithm?: jwt.Algorithm;
	expiresIn?: number;
	payload?: Record<string, unknown>;
}

interface EndpointConfig {
	name: string;
	url: string;
	method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
	headers?: Record<string, string>;
	auth?: AuthConfig;
	defaultBody?: Record<string, unknown>;
	stream?: boolean; // Enable SSE streaming and parsing
	debug?: {
		// Paths to log files for debugging (relative to cwd)
		backendLogs?: string;
		workflowLogs?: string;
	};
}

// Template field: user-defined input field for templates
interface TemplateFieldConfig {
	name: string;           // Field identifier
	label: string;          // Display label (e.g., "Prompt")
	hint?: string;          // Optional hint (e.g., "→ positive_prompt")
	type?: "text" | "multiline" | "json";  // Default: "multiline"
	path?: string;          // JSON path to inject value (e.g., "generation_params.positive_prompt")
	required?: boolean;     // Whether field is required
	default?: string;       // Default value
	appendTo?: string;      // Name of another field to append this value to (instead of using path)
	appendFormat?: string;  // Format string when appending, use {value} as placeholder (default: "\n\n{value}")
}

// Template: pre-configured request for quick access
interface TemplateConfig {
	name: string;
	description?: string;
	endpoint: string; // Reference to @endpoint name
	body?: Record<string, unknown>; // Overrides/merges with endpoint's defaultBody
	headers?: Record<string, string>; // Extra headers
	fields?: TemplateFieldConfig[]; // User-defined input fields
	appendField?: boolean; // Auto-add "Additional Instructions" field that appends to first field
}

// Parsed SSE result for streaming responses
interface SSEOutput {
	file_type: string;
	width: number;
	height: number;
	bucket_name: string;
	object_key: string;
	size_bytes: string;
	inference_request_id: string;
}

interface SSEParseResult {
	responseText: string; // Accumulated text from text-delta events
	outputs: SSEOutput[];
	errors: string[];
	toolCalls: Array<{ name: string; input: unknown }>;
	restructuredPrompt?: string;
}

// Custom logging configuration for project-specific generation output
interface CustomLoggingConfig {
	enabled: boolean;
	outputDir: string; // e.g., "~/Desktop/api-generations"
	logs?: Record<string, string>; // Map of log name to path, e.g., { "backend": "/tmp/output.txt", "workflow": "apps/logs/dev.log" }
	postScript?: string; // Optional path to custom post-processing script (receives output dir as argument)
}

interface SuperCurlConfig {
	baseUrl?: string;
	auth?: AuthConfig;
	headers?: Record<string, string>;
	endpoints?: EndpointConfig[];
	templates?: TemplateConfig[]; // Pre-configured request templates
	timeout?: number;
	envFile?: string; // Path to .env file (relative to project or absolute)
	customLogging?: CustomLoggingConfig; // Optional project-specific generation logging
}

// Loaded environment variables from envFile
let loadedEnv: Record<string, string> = {};

// Request builder result
interface RequestBuilderResult {
	method: string;
	url: string;
	body: string;
	headers: string;
	cancelled: boolean;
	endpoint?: string; // Selected endpoint name
}

// History entry for storing past requests
interface HistoryEntry {
	id: string;
	timestamp: number;
	method: string;
	url: string;
	body?: string;
	headers?: Record<string, string>;
	endpoint?: string;
	template?: string;
}

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
const HISTORY_PATH = path.join(os.homedir(), ".super-curl-history.json");
const MAX_HISTORY = 50;

export default function superCurlExtension(pi: ExtensionAPI) {
	let config: SuperCurlConfig = {};
	let configDir: string = ""; // Directory where config was loaded from

	// Auto-setup: Create skill and agent symlinks if they don't exist
	function setupSymlinks() {
		const piSkillsDir = path.join(os.homedir(), ".pi", "agent", "skills");
		const piAgentsDir = path.join(os.homedir(), ".pi", "agent", "agents");
		
		// Find the extension directory (where this script is running from)
		const extensionDir = path.dirname(new URL(import.meta.url).pathname);
		
		// Ensure directories exist
		if (!fs.existsSync(piSkillsDir)) {
			fs.mkdirSync(piSkillsDir, { recursive: true });
		}
		if (!fs.existsSync(piAgentsDir)) {
			fs.mkdirSync(piAgentsDir, { recursive: true });
		}
		
		// Create skill symlink: ~/.pi/agent/skills/send-request -> extension/skills/send-request
		const skillSource = path.join(extensionDir, "skills", "send-request");
		const skillTarget = path.join(piSkillsDir, "send-request");
		if (fs.existsSync(skillSource) && !fs.existsSync(skillTarget)) {
			try {
				fs.symlinkSync(skillSource, skillTarget, "dir");
			} catch (e) {
				// Ignore errors (e.g., permission denied)
			}
		}
		
		// Create agent symlink: ~/.pi/agent/agents/api-tester.md -> extension/agents/api-tester.md
		const agentSource = path.join(extensionDir, "agents", "api-tester.md");
		const agentTarget = path.join(piAgentsDir, "api-tester.md");
		if (fs.existsSync(agentSource) && !fs.existsSync(agentTarget)) {
			try {
				fs.symlinkSync(agentSource, agentTarget, "file");
			} catch (e) {
				// Ignore errors
			}
		}
	}
	
	// Run setup on extension load
	setupSymlinks();

	// Load configuration
	function loadConfig(cwd: string): SuperCurlConfig {
		// Config location: .pi-super-curl/config.json
		// Search order: project directory, then home directory
		const configPaths = [
			{ path: path.join(cwd, ".pi-super-curl", "config.json"), dir: path.join(cwd, ".pi-super-curl") },
			{ path: path.join(os.homedir(), ".pi-super-curl", "config.json"), dir: path.join(os.homedir(), ".pi-super-curl") },
		];

		for (const { path: configPath, dir } of configPaths) {
			if (fs.existsSync(configPath)) {
				try {
					const content = fs.readFileSync(configPath, "utf-8");
					const cfg = JSON.parse(content) as SuperCurlConfig;
					configDir = dir;
					
					// Load env file if specified
					if (cfg.envFile) {
						loadEnvFile(cwd, cfg.envFile);
					}
					
					return cfg;
				} catch (e) {
					// Ignore parse errors
				}
			}
		}
		configDir = cwd;
		return {};
	}

	// Load environment file
	function loadEnvFile(cwd: string, envFile: string) {
		let envPath = envFile;
		
		// Handle relative paths
		if (!path.isAbsolute(envFile)) {
			if (envFile.startsWith("~")) {
				envPath = path.join(os.homedir(), envFile.slice(1));
			} else {
				envPath = path.join(cwd, envFile);
			}
		}

		if (fs.existsSync(envPath)) {
			const result = dotenv.config({ path: envPath });
			if (result.parsed) {
				loadedEnv = { ...loadedEnv, ...result.parsed };
			}
		}
	}

	// ===== History Management =====
	
	function loadHistory(): HistoryEntry[] {
		try {
			if (fs.existsSync(HISTORY_PATH)) {
				const content = fs.readFileSync(HISTORY_PATH, "utf-8");
				return JSON.parse(content) as HistoryEntry[];
			}
		} catch {
			// Ignore errors, return empty
		}
		return [];
	}

	function saveHistory(history: HistoryEntry[]): void {
		try {
			fs.writeFileSync(HISTORY_PATH, JSON.stringify(history, null, 2));
		} catch {
			// Ignore write errors
		}
	}

	function addToHistory(entry: Omit<HistoryEntry, "id" | "timestamp">): void {
		const history = loadHistory();
		const newEntry: HistoryEntry = {
			...entry,
			id: uuidv4(),
			timestamp: Date.now(),
		};
		history.unshift(newEntry);
		saveHistory(history.slice(0, MAX_HISTORY));
	}

	function deleteFromHistory(id: string): void {
		const history = loadHistory();
		const filtered = history.filter(h => h.id !== id);
		saveHistory(filtered);
	}

	function clearHistory(): void {
		saveHistory([]);
	}

	function formatHistoryEntry(entry: HistoryEntry): string {
		const date = new Date(entry.timestamp);
		const timeStr = date.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
		const dateStr = date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
		const url = entry.endpoint ? `@${entry.endpoint}` : entry.url;
		const truncatedUrl = url.length > 40 ? url.slice(0, 37) + "..." : url;
		return `${entry.method.padEnd(6)} ${truncatedUrl.padEnd(42)} ${dateStr} ${timeStr}`;
	}

	// ===== cURL Parser =====

	interface ParsedCurl {
		method: string;
		url: string;
		headers: Record<string, string>;
		body?: string;
		error?: string;
	}

	function parseCurl(curlCommand: string): ParsedCurl {
		const result: ParsedCurl = {
			method: "GET",
			url: "",
			headers: {},
		};

		// Normalize: remove line continuations and extra whitespace
		let cmd = curlCommand
			.replace(/\\\s*\n/g, " ")  // Remove line continuations
			.replace(/\s+/g, " ")       // Normalize whitespace
			.trim();

		// Remove 'curl' prefix if present
		if (cmd.toLowerCase().startsWith("curl ")) {
			cmd = cmd.slice(5).trim();
		}

		// Tokenize respecting quotes
		const tokens: string[] = [];
		let current = "";
		let inQuote: string | null = null;
		let escape = false;

		for (let i = 0; i < cmd.length; i++) {
			const char = cmd[i];

			if (escape) {
				current += char;
				escape = false;
				continue;
			}

			if (char === "\\") {
				escape = true;
				continue;
			}

			if (inQuote) {
				if (char === inQuote) {
					inQuote = null;
				} else {
					current += char;
				}
			} else {
				if (char === '"' || char === "'") {
					inQuote = char;
				} else if (char === " ") {
					if (current) {
						tokens.push(current);
						current = "";
					}
				} else {
					current += char;
				}
			}
		}
		if (current) tokens.push(current);

		// Parse tokens
		let i = 0;
		while (i < tokens.length) {
			const token = tokens[i];

			// Method
			if (token === "-X" || token === "--request") {
				i++;
				if (i < tokens.length) {
					result.method = tokens[i].toUpperCase();
				}
				i++;
				continue;
			}

			// Headers
			if (token === "-H" || token === "--header") {
				i++;
				if (i < tokens.length) {
					const header = tokens[i];
					const colonIdx = header.indexOf(":");
					if (colonIdx > 0) {
						const key = header.slice(0, colonIdx).trim();
						const value = header.slice(colonIdx + 1).trim();
						result.headers[key] = value;
					}
				}
				i++;
				continue;
			}

			// Data/Body
			if (token === "-d" || token === "--data" || token === "--data-raw" || token === "--data-binary") {
				i++;
				if (i < tokens.length) {
					result.body = tokens[i];
					// If we have a body and method is still GET, assume POST
					if (result.method === "GET") {
						result.method = "POST";
					}
				}
				i++;
				continue;
			}

			// JSON shorthand (some curl versions)
			if (token === "--json") {
				i++;
				if (i < tokens.length) {
					result.body = tokens[i];
					result.headers["Content-Type"] = "application/json";
					if (result.method === "GET") {
						result.method = "POST";
					}
				}
				i++;
				continue;
			}

			// Skip common flags we don't need
			if (token === "-i" || token === "--include" ||
				token === "-s" || token === "--silent" ||
				token === "-S" || token === "--show-error" ||
				token === "-v" || token === "--verbose" ||
				token === "-k" || token === "--insecure" ||
				token === "-L" || token === "--location" ||
				token === "-f" || token === "--fail" ||
				token === "-o" || token === "--output" ||
				token === "-O" || token === "--remote-name" ||
				token === "-w" || token === "--write-out" ||
				token === "-A" || token === "--user-agent" ||
				token === "-e" || token === "--referer" ||
				token === "-b" || token === "--cookie" ||
				token === "-c" || token === "--cookie-jar" ||
				token === "--compressed" ||
				token === "--http1.1" || token === "--http2") {
				// Some of these take an argument
				if (token === "-o" || token === "--output" ||
					token === "-w" || token === "--write-out" ||
					token === "-A" || token === "--user-agent" ||
					token === "-e" || token === "--referer" ||
					token === "-b" || token === "--cookie" ||
					token === "-c" || token === "--cookie-jar") {
					i++; // Skip the argument too
				}
				i++;
				continue;
			}

			// Timeout
			if (token === "--connect-timeout" || token === "-m" || token === "--max-time") {
				i += 2; // Skip flag and value
				continue;
			}

			// URL (anything that looks like a URL or doesn't start with -)
			if (!token.startsWith("-") && !result.url) {
				result.url = token;
			}

			i++;
		}

		if (!result.url) {
			result.error = "No URL found in cURL command";
		}

		return result;
	}

	function formatCurlExport(method: string, url: string, headers: Record<string, string>, body?: string): string {
		let curl = `curl -X ${method}`;
		
		for (const [key, value] of Object.entries(headers)) {
			// Escape single quotes in header values
			const escapedValue = value.replace(/'/g, "'\\''");
			curl += ` \\\n  -H '${key}: ${escapedValue}'`;
		}
		
		if (body) {
			// Escape single quotes in body
			const escapedBody = body.replace(/'/g, "'\\''");
			curl += ` \\\n  -d '${escapedBody}'`;
		}
		
		curl += ` \\\n  '${url}'`;
		
		return curl;
	}

	// Resolve env var values (from $VAR syntax)
	function resolveValue(value: string | undefined): string | undefined {
		if (!value) return undefined;
		if (value.startsWith("$")) {
			const varName = value.slice(1);
			// Check loaded env first, then process.env
			return loadedEnv[varName] || process.env[varName];
		}
		return value;
	}

	// Resolve template variables in a string
	// Supports: {{uuid}}, {{uuidv7}}, {{timestamp}}, {{env.VAR_NAME}}, {{$VAR_NAME}}
	function resolveTemplates(text: string): string {
		return text.replace(/\{\{([^}]+)\}\}/g, (match, expr) => {
			const trimmed = expr.trim();
			
			// {{uuid}} or {{uuidv4}} - random UUID v4
			if (trimmed === "uuid" || trimmed === "uuidv4") {
				return uuidv4();
			}
			
			// {{uuidv7}} - time-ordered UUID v7
			if (trimmed === "uuidv7") {
				return uuidv7();
			}
			
			// {{timestamp}} - Unix timestamp in seconds
			if (trimmed === "timestamp") {
				return Math.floor(Date.now() / 1000).toString();
			}
			
			// {{timestamp_ms}} - Unix timestamp in milliseconds
			if (trimmed === "timestamp_ms") {
				return Date.now().toString();
			}
			
			// {{date}} - ISO date string
			if (trimmed === "date") {
				return new Date().toISOString();
			}
			
			// {{env.VAR_NAME}} or {{$VAR_NAME}} - environment variable
			if (trimmed.startsWith("env.")) {
				const varName = trimmed.slice(4);
				return loadedEnv[varName] || process.env[varName] || "";
			}
			if (trimmed.startsWith("$")) {
				const varName = trimmed.slice(1);
				return loadedEnv[varName] || process.env[varName] || "";
			}
			
			// Unknown template, return as-is
			return match;
		});
	}

	// Resolve templates in an object (deep)
	function resolveTemplatesInObject(obj: unknown): unknown {
		if (typeof obj === "string") {
			return resolveTemplates(obj);
		}
		if (Array.isArray(obj)) {
			return obj.map(resolveTemplatesInObject);
		}
		if (obj && typeof obj === "object") {
			const result: Record<string, unknown> = {};
			for (const [key, value] of Object.entries(obj)) {
				result[key] = resolveTemplatesInObject(value);
			}
			return result;
		}
		return obj;
	}

	// Parse SSE stream for streaming responses
	function parseSSEResponse(rawResponse: string): SSEParseResult {
		const result: SSEParseResult = {
			responseText: "",
			outputs: [],
			errors: [],
			toolCalls: [],
		};

		const lines = rawResponse.split("\n");
		for (const line of lines) {
			if (!line.startsWith("data: ") || line === "data: [DONE]") continue;

			try {
				const data = JSON.parse(line.slice(6));

				// Capture text deltas
				if (data.type === "text-delta" && data.delta) {
					result.responseText += data.delta;
				}

				// Capture errors
				if (data.type === "error" || data.error) {
					result.errors.push(data.error || data.message || JSON.stringify(data));
				}

				// Capture tool inputs (for debugging what was sent)
				if (data.type === "tool-input-available" && data.input) {
					result.toolCalls.push({ name: data.toolName, input: data.input });
					
					// Extract restructured prompts from generation tools
					const promptFields = [
						"image_to_image_prompt",
						"video_prompt",
						"text_to_image_prompt",
						"image_to_video_prompt",
						"audio_prompt",
					];
					for (const field of promptFields) {
						if (data.input[field]) {
							result.restructuredPrompt = data.input[field];
							break;
						}
					}
				}

				// Capture completed file outputs (non-preliminary)
				if (data.type === "tool-output-available" && !data.preliminary && data.output?.parts) {
					for (const part of data.output.parts) {
						if (part.type === "file" && part.state === "completed" && part.bucket_name) {
							result.outputs.push({
								file_type: part.file_type,
								width: part.width,
								height: part.height,
								bucket_name: part.bucket_name,
								object_key: part.object_key,
								size_bytes: part.size_bytes,
								inference_request_id: part.inference_request_id,
							});
						}
					}
				}
			} catch {
				// Ignore JSON parse errors for non-JSON lines
			}
		}

		return result;
	}

	// Read log file contents (with size limit)
	function readLogFile(cwd: string, logPath: string, maxBytes = 50000): string | null {
		try {
			let fullPath = logPath;
			if (!path.isAbsolute(logPath)) {
				fullPath = path.join(cwd, logPath);
			}
			
			if (!fs.existsSync(fullPath)) return null;
			
			const stats = fs.statSync(fullPath);
			const fd = fs.openSync(fullPath, "r");
			
			// Read last maxBytes of the file
			const readSize = Math.min(stats.size, maxBytes);
			const offset = Math.max(0, stats.size - readSize);
			const buffer = Buffer.alloc(readSize);
			fs.readSync(fd, buffer, 0, readSize, offset);
			fs.closeSync(fd);
			
			let content = buffer.toString("utf-8");
			if (offset > 0) {
				content = `[... truncated ${offset} bytes ...]\n` + content;
			}
			return content;
		} catch {
			return null;
		}
	}

	// Build debug info for failed requests
	function buildDebugInfo(cwd: string, endpoint: EndpointConfig | undefined, sseResult: SSEParseResult | null): string {
		let debug = "\n\n=== DEBUG INFO ===\n";

		// Add SSE-parsed info if available
		if (sseResult) {
			if (sseResult.errors.length > 0) {
				debug += "\n[!] Errors from response:\n";
				for (const err of sseResult.errors) {
					debug += `  - ${err}\n`;
				}
			}

			if (sseResult.restructuredPrompt) {
				debug += `\n[>] Restructured prompt: "${sseResult.restructuredPrompt}"\n`;
			}

			if (sseResult.toolCalls.length > 0) {
				debug += "\n[*] Tool calls made:\n";
				for (const tc of sseResult.toolCalls) {
					debug += `  - ${tc.name}\n`;
				}
			}

			if (sseResult.outputs.length > 0) {
				debug += "\n[OK] Generated outputs:\n";
				for (const out of sseResult.outputs) {
					debug += `  - ${out.file_type} (${out.width}x${out.height}) → gs://${out.bucket_name}/${out.object_key}\n`;
				}
			} else if (sseResult.responseText && !sseResult.errors.length) {
				debug += "\n[WARN] No file outputs detected (might be text-only response or still processing)\n";
			}
		}

		// Add log file locations
		if (endpoint?.debug) {
			debug += "\n[DIR] Log files to check:\n";
			
			if (endpoint.debug.backendLogs) {
				const fullPath = path.isAbsolute(endpoint.debug.backendLogs) 
					? endpoint.debug.backendLogs 
					: path.join(cwd, endpoint.debug.backendLogs);
				debug += `  - Backend logs: ${fullPath}\n`;
				
				const logs = readLogFile(cwd, endpoint.debug.backendLogs, 10000);
				if (logs) {
					debug += "\n--- Last backend logs ---\n";
					debug += logs.split("\n").slice(-50).join("\n");
					debug += "\n--- End backend logs ---\n";
				}
			}
			
			if (endpoint.debug.workflowLogs) {
				const fullPath = path.isAbsolute(endpoint.debug.workflowLogs)
					? endpoint.debug.workflowLogs
					: path.join(cwd, endpoint.debug.workflowLogs);
				debug += `  - Workflow logs: ${fullPath}\n`;
				
				const logs = readLogFile(cwd, endpoint.debug.workflowLogs, 10000);
				if (logs) {
					debug += "\n--- Last workflow logs ---\n";
					debug += logs.split("\n").slice(-50).join("\n");
					debug += "\n--- End workflow logs ---\n";
				}
			}
		}

		return debug;
	}

	// Generate JWT token
	function generateJwtToken(auth: AuthConfig): string {
		const secret = resolveValue(auth.secret);
		if (!secret) {
			throw new Error("JWT secret not found. Check your config and env file.");
		}

		// Build payload with template resolution
		const payload = resolveTemplatesInObject(auth.payload || {}) as jwt.JwtPayload;
		
		// Add standard JWT claims if not present
		const now = Math.floor(Date.now() / 1000);
		if (!payload.iat) payload.iat = now;
		if (!payload.exp) payload.exp = now + (auth.expiresIn || 3600);

		return jwt.sign(payload, secret, { 
			algorithm: auth.algorithm || "HS256" 
		});
	}

	// Build auth header
	function buildAuthHeader(auth: AuthConfig): Record<string, string> {
		const headers: Record<string, string> = {};

		switch (auth.type) {
			case "bearer": {
				const token = resolveValue(auth.token);
				if (token) headers["Authorization"] = `Bearer ${token}`;
				break;
			}
			case "api-key": {
				const token = resolveValue(auth.token);
				if (token) headers[auth.header || "X-API-Key"] = token;
				break;
			}
			case "basic": {
				const username = resolveValue(auth.username) || "";
				const password = resolveValue(auth.password) || "";
				headers["Authorization"] = `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
				break;
			}
			case "jwt": {
				const token = generateJwtToken(auth);
				headers["Authorization"] = `Bearer ${token}`;
				break;
			}
		}
		return headers;
	}

	// Log generation outputs to directory (like send-message skill)
	interface GenerationLogParams {
		cwd: string;
		prompt: string;
		restructuredPrompt?: string;
		chatId?: string;
		generationMode?: string;
		outputs: SSEOutput[];
		responseText?: string;
		errors: string[];
	}

	function logGeneration(params: GenerationLogParams): string[] {
		// Use customLogging.outputDir if enabled, otherwise skip
		if (!config.customLogging?.enabled || !config.customLogging?.outputDir) {
			return [];
		}
		
		const outputDir = config.customLogging.outputDir.startsWith("~")
			? path.join(os.homedir(), config.customLogging.outputDir.slice(1))
			: path.resolve(params.cwd, config.customLogging.outputDir);
		
		if (!outputDir) return [];

		const loggedPaths: string[] = [];
		const timestamp = new Date().toISOString();
		const dateStr = new Date().toLocaleDateString("en-US", {
			weekday: "long", year: "numeric", month: "long", day: "numeric"
		});
		const timeStr = new Date().toLocaleTimeString("en-US");

		// Ensure base directory exists
		if (!fs.existsSync(outputDir)) {
			fs.mkdirSync(outputDir, { recursive: true });
		}

		// Handle error case (no outputs)
		if (params.outputs.length === 0) {
			const errorId = `error-${Date.now()}`;
			const errorDir = path.join(outputDir, errorId);
			fs.mkdirSync(errorDir, { recursive: true });

			let content = "";
			content += "Generation Error\n";
			content += "================\n\n";
			content += `Date: ${dateStr} at ${timeStr}\n`;
			content += `Timestamp: ${timestamp}\n\n`;
			content += `Original Prompt: ${params.prompt}\n`;
			if (params.restructuredPrompt && params.restructuredPrompt !== params.prompt) {
				content += `Restructured Prompt: ${params.restructuredPrompt}\n`;
			}
			content += `\nMode: ${params.generationMode || "unknown"}\n`;
			if (params.chatId) content += `Chat ID: ${params.chatId}\n`;
			content += `\nAgent Response:\n${"─".repeat(40)}\n`;
			content += params.responseText || "(no response captured)";
			content += "\n";

			if (params.errors.length > 0) {
				content += `\nErrors:\n${"─".repeat(40)}\n`;
				for (const err of params.errors) {
					content += `• ${err}\n`;
				}
			}

			fs.writeFileSync(path.join(errorDir, "errors.txt"), content);
			loggedPaths.push(errorDir);

			// Copy logs
			copyCustomLogs(params.cwd, errorDir);
			return loggedPaths;
		}

		// Process each output
		for (const output of params.outputs) {
			const inferenceId = output.inference_request_id;
			const outDir = path.join(outputDir, inferenceId);
			
			if (!fs.existsSync(outDir)) {
				fs.mkdirSync(outDir, { recursive: true });
			}

			const gcsUrl = `gs://${output.bucket_name}/${output.object_key}`;
			const fileExt = output.object_key.split(".").pop() || "png";
			const outputFileName = `output.${fileExt}`;

			// Write info.txt
			let info = "";
			info += "Generation Info\n";
			info += "===============\n\n";
			info += `Date: ${dateStr} at ${timeStr}\n`;
			info += `Timestamp: ${timestamp}\n\n`;
			info += `Original Prompt: ${params.prompt}\n`;
			if (params.restructuredPrompt && params.restructuredPrompt !== params.prompt) {
				info += `Restructured Prompt: ${params.restructuredPrompt}\n`;
			}
			info += `\nMode: ${params.generationMode || "unknown"}\n`;
			if (params.chatId) info += `Chat ID: ${params.chatId}\n`;
			info += `Inference Request ID: ${inferenceId}\n\n`;
			info += "Output Details:\n";
			info += `  - Type: ${output.file_type}\n`;
			info += `  - Dimensions: ${output.width}x${output.height}\n`;
			if (output.size_bytes) {
				info += `  - Size: ${(parseInt(output.size_bytes) / 1024 / 1024).toFixed(2)} MB\n`;
			}
			info += `  - GCS URL: ${gcsUrl}\n`;
			info += `  - Local File: ${outputFileName}\n`;

			fs.writeFileSync(path.join(outDir, "info.txt"), info);

			// Try to download from GCS
			const outputFilePath = path.join(outDir, outputFileName);
			try {
				const { execSync } = require("child_process");
				execSync(`gsutil cp "${gcsUrl}" "${outputFilePath}"`, { stdio: "pipe" });
			} catch {
				// Save GCS URL for manual download
				fs.writeFileSync(path.join(outDir, "gcs_url.txt"), gcsUrl);
			}

			// Copy logs for first output only
			if (output === params.outputs[0]) {
				copyCustomLogs(params.cwd, outDir);
			}

			loggedPaths.push(outDir);
		}

		return loggedPaths;
	}

	// Copy log files defined in customLogging.logs config
	function copyCustomLogs(cwd: string, destDir: string): void {
		const logs = config.customLogging?.logs;
		if (!logs) return;

		for (const [name, logPath] of Object.entries(logs)) {
			// Resolve path (absolute or relative to cwd)
			const src = path.isAbsolute(logPath) 
				? logPath 
				: path.resolve(cwd, logPath);
			
			if (fs.existsSync(src)) {
				const dest = path.join(destDir, `${name}-logs.txt`);
				try {
					fs.copyFileSync(src, dest);
				} catch {
					// Ignore copy errors
				}
			}
		}
	}

	// /scurl command - opens UI then delegates to api-tester subagent
	pi.registerCommand("scurl", {
		description: "Open Super Curl request builder (Ctrl+T for templates)",
		handler: async (_args, ctx) => {
			config = loadConfig(ctx.cwd);

			// Build template list for template mode
			interface TemplateOption {
				name: string;
				label: string;
				description?: string;
				endpoint?: EndpointConfig;
				bodyOverrides?: Record<string, unknown>;
				extraHeaders?: Record<string, string>;
				fields?: TemplateFieldConfig[];
				appendField?: boolean;
			}
			
			const templateOptions: TemplateOption[] = [];
			
			if (config.templates && config.templates.length > 0) {
				for (const tpl of config.templates) {
					const ep = config.endpoints?.find(e => e.name === tpl.endpoint);
					templateOptions.push({
						name: tpl.name,
						label: tpl.description || `${tpl.name} → @${tpl.endpoint}`,
						description: tpl.description,
						endpoint: ep,
						bodyOverrides: tpl.body,
						extraHeaders: tpl.headers,
						fields: tpl.fields,
						appendField: tpl.appendField,
					});
				}
			} else {
				for (const ep of config.endpoints || []) {
					templateOptions.push({
						name: ep.name,
						label: `@${ep.name} (${ep.method || "GET"})`,
						endpoint: ep,
					});
				}
			}

			const result = await ctx.ui.custom<RequestBuilderResult>((tui, theme, _kb, done) => {
				let mode: "template" | "default" = "default";
				let endpointIndex = 0;
				let bodyScrollOffset = 0;
				const bodyMaxVisible = 8;
				let methodIndex = 0;
				let fieldEditors: Map<string, Editor> = new Map();
				let templateFieldIndex = 0;
				type CustomField = "method" | "url" | "body" | "headers";
				let customField: CustomField = "method";
				let cachedLines: string[] | undefined;
				
				// cURL import popup state
				let showCurlImport = false;
				let curlImportError: string | null = null;

				const editorTheme: EditorTheme = {
					borderColor: (s) => theme.fg("accent", s),
					selectList: {
						selectedPrefix: (t) => theme.fg("accent", t),
						selectedText: (t) => theme.fg("accent", t),
						description: (t) => theme.fg("muted", t),
						scrollInfo: (t) => theme.fg("dim", t),
						noMatch: (t) => theme.fg("warning", t),
					},
				};

				const urlEditor = new Editor(tui, editorTheme);
				const bodyEditor = new Editor(tui, editorTheme);
				const headersEditor = new Editor(tui, editorTheme);
				const curlEditor = new Editor(tui, editorTheme);

				// Apply parsed cURL to form fields
				function applyCurl(parsed: ParsedCurl): void {
					// Set method
					const methodIdx = METHODS.indexOf(parsed.method as typeof METHODS[number]);
					if (methodIdx >= 0) {
						methodIndex = methodIdx;
					}
					
					// Set URL
					urlEditor.setText(parsed.url);
					
					// Set headers
					const headerLines = Object.entries(parsed.headers)
						.map(([k, v]) => `${k}: ${v}`)
						.join("\n");
					headersEditor.setText(headerLines);
					
					// Set body
					if (parsed.body) {
						// Try to pretty-print JSON
						try {
							const jsonBody = JSON.parse(parsed.body);
							bodyEditor.setText(JSON.stringify(jsonBody, null, 2));
						} catch {
							bodyEditor.setText(parsed.body);
						}
					} else {
						bodyEditor.setText("");
					}
					
					// Switch to default mode to show the imported request
					mode = "default";
					customField = "url";
				}

				const defaultPromptField: TemplateFieldConfig = {
					name: "prompt",
					label: "",
					path: "generation_params.positive_prompt",
				};
				
				// Auto-generated instructions field for appendField: true
				const autoInstructionsField: TemplateFieldConfig = {
					name: "instructions",
					label: "Additional Instructions",
					hint: "Appended to prompt",
					appendTo: "prompt",
					appendFormat: "\n\nAdditional instructions: {value}",
				};
				
				function getTemplateFields(): string[] {
					const fields = ["endpoint"];
					const tpl = templateOptions[endpointIndex];
					if (tpl?.fields && tpl.fields.length > 0) {
						for (const f of tpl.fields) fields.push(f.name);
					} else {
						fields.push("prompt");
					}
					// Add instructions field if appendField is enabled
					if (tpl?.appendField) {
						fields.push("instructions");
					}
					fields.push("body");
					return fields;
				}
				
				function getTemplateFieldConfigs(): TemplateFieldConfig[] {
					const tpl = templateOptions[endpointIndex];
					let configs: TemplateFieldConfig[] = [];
					if (tpl?.fields && tpl.fields.length > 0) {
						configs = [...tpl.fields];
					} else {
						configs = [defaultPromptField];
					}
					// Auto-add instructions field if appendField is enabled
					if (tpl?.appendField) {
						// Find the first field to use as appendTo target
						const firstFieldName = configs[0]?.name || "prompt";
						configs.push({
							...autoInstructionsField,
							appendTo: firstFieldName,
						});
					}
					return configs;
				}
				
				function getCurrentTemplateField(): string {
					const fields = getTemplateFields();
					return fields[templateFieldIndex] || "endpoint";
				}
				
				function getFieldEditor(fieldName: string): Editor {
					if (!fieldEditors.has(fieldName)) {
						const editor = new Editor(tui, editorTheme);
						const tpl = templateOptions[endpointIndex];
						const fieldConfig = tpl?.fields?.find(f => f.name === fieldName);
						if (fieldConfig?.default) editor.setText(fieldConfig.default);
						fieldEditors.set(fieldName, editor);
					}
					return fieldEditors.get(fieldName)!;
				}

				function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
					const result = { ...target };
					for (const key of Object.keys(source)) {
						if (source[key] && typeof source[key] === "object" && !Array.isArray(source[key])) {
							if (target[key] && typeof target[key] === "object" && !Array.isArray(target[key])) {
								result[key] = deepMerge(target[key] as Record<string, unknown>, source[key] as Record<string, unknown>);
							} else {
								result[key] = source[key];
							}
						} else {
							result[key] = source[key];
						}
					}
					return result;
				}

				function loadTemplate(idx: number) {
					if (idx < 0 || idx >= templateOptions.length) return;
					const opt = templateOptions[idx];
					bodyScrollOffset = 0;
					if (opt.endpoint) {
						const methodIdx = METHODS.indexOf(opt.endpoint.method || "GET");
						if (methodIdx >= 0) methodIndex = methodIdx;
						
						let body: Record<string, unknown> = {};
						if (opt.endpoint.defaultBody) {
							body = JSON.parse(JSON.stringify(opt.endpoint.defaultBody));
						}
						if (opt.bodyOverrides) {
							body = deepMerge(body, opt.bodyOverrides);
						}
						
						if (Object.keys(body).length > 0) {
							bodyEditor.setText(JSON.stringify(body, null, 2));
						} else {
							bodyEditor.setText("");
						}
						
						if (opt.extraHeaders) {
							const headerLines = Object.entries(opt.extraHeaders)
								.map(([k, v]) => `${k}: ${v}`)
								.join("\n");
							headersEditor.setText(headerLines);
						} else {
							headersEditor.setText("");
						}
						
						fieldEditors = new Map();
						const fieldsToSetup = (opt.fields && opt.fields.length > 0) ? opt.fields : [defaultPromptField];
						for (const f of fieldsToSetup) {
							const editor = new Editor(tui, editorTheme);
							if (f.default) editor.setText(f.default);
							fieldEditors.set(f.name, editor);
						}
						
						templateFieldIndex = 0;
					}
				}

				function refresh() {
					cachedLines = undefined;
					tui.requestRender();
				}

				function getActiveEditor(): Editor | null {
					if (mode === "template") {
						const currentField = getCurrentTemplateField();
						if (currentField === "endpoint") return null;
						if (currentField === "body") return bodyEditor;
						if (currentField === "headers") return headersEditor;
						return getFieldEditor(currentField);
					} else {
						switch (customField) {
							case "url": return urlEditor;
							case "body": return bodyEditor;
							case "headers": return headersEditor;
							default: return null;
						}
					}
				}

				// Set value at a JSON path (e.g., "generation_params.positive_prompt" or "messages[0].content")
				function setAtPath(obj: Record<string, unknown>, pathStr: string, value: unknown): void {
					// Parse path into segments, handling both dot notation and array brackets
					const segments: (string | number)[] = [];
					const regex = /([^.\[\]]+)|\[(\d+)\]/g;
					let match;
					while ((match = regex.exec(pathStr)) !== null) {
						if (match[1] !== undefined) {
							segments.push(match[1]); // property name
						} else if (match[2] !== undefined) {
							segments.push(parseInt(match[2], 10)); // array index
						}
					}
					
					let current: unknown = obj;
					for (let i = 0; i < segments.length - 1; i++) {
						const seg = segments[i];
						const nextSeg = segments[i + 1];
						const currentObj = current as Record<string, unknown>;
						
						if (!(seg in currentObj) || typeof currentObj[seg as string] !== "object") {
							// Create array or object based on next segment type
							currentObj[seg as string] = typeof nextSeg === "number" ? [] : {};
						}
						current = currentObj[seg as string];
					}
					
					const lastSeg = segments[segments.length - 1];
					(current as Record<string, unknown>)[lastSeg as string] = value;
				}

				function buildFinalBody(): string {
					const bodyText = bodyEditor.getText().trim();
					if (mode === "template") {
						const fieldConfigs = getTemplateFieldConfigs();
						try {
							const body = bodyText ? JSON.parse(bodyText) : {};
							
							// First pass: collect all field values
							const fieldValues: Map<string, string> = new Map();
							for (const fieldConfig of fieldConfigs) {
								const editor = fieldEditors.get(fieldConfig.name);
								const value = editor?.getText().trim() || "";
								fieldValues.set(fieldConfig.name, value);
							}
							
							// Second pass: process appendTo fields (append their value to target field)
							for (const fieldConfig of fieldConfigs) {
								if (!fieldConfig.appendTo) continue;
								const appendValue = fieldValues.get(fieldConfig.name) || "";
								if (!appendValue) continue; // Skip if nothing to append
								
								const targetValue = fieldValues.get(fieldConfig.appendTo) || "";
								const format = fieldConfig.appendFormat || "\n\n{value}";
								const formattedAppend = format.replace("{value}", appendValue);
								fieldValues.set(fieldConfig.appendTo, targetValue + formattedAppend);
							}
							
							// Third pass: set values at their paths (skip appendTo fields as they don't have their own path)
							for (const fieldConfig of fieldConfigs) {
								if (!fieldConfig.path || fieldConfig.appendTo) continue;
								const value = fieldValues.get(fieldConfig.name) || "";
								if (value) setAtPath(body, fieldConfig.path, value);
							}
							
							return JSON.stringify(body);
						} catch {
							return bodyText;
						}
					}
					return bodyText;
				}

				function getUrl(): string {
					if (mode === "template" && templateOptions.length > 0) {
						const tpl = templateOptions[endpointIndex];
						return `@${tpl.endpoint?.name || tpl.name}`;
					}
					return urlEditor.getText().trim();
				}

				function submit() {
					done({
						method: METHODS[methodIndex],
						url: getUrl(),
						body: buildFinalBody(),
						headers: headersEditor.getText().trim(),
						cancelled: false,
						endpoint: mode === "template" ? templateOptions[endpointIndex]?.name : undefined,
					});
				}

				function handleInput(data: string) {
					// Handle cURL import popup
					if (showCurlImport) {
						if (matchesKey(data, Key.escape)) {
							showCurlImport = false;
							curlImportError = null;
							curlEditor.setText("");
							refresh();
							return;
						}

						if (matchesKey(data, Key.ctrl("enter")) || matchesKey(data, Key.ctrl("j"))) {
							const curlText = curlEditor.getText().trim();
							if (!curlText) {
								curlImportError = "Please paste a cURL command";
								refresh();
								return;
							}

							const parsed = parseCurl(curlText);
							if (parsed.error) {
								curlImportError = parsed.error;
								refresh();
								return;
							}

							// Apply parsed cURL to form
							applyCurl(parsed);
							showCurlImport = false;
							curlImportError = null;
							curlEditor.setText("");
							refresh();
							return;
						}

						// Forward to cURL editor
						curlEditor.handleInput(data);
						curlImportError = null; // Clear error on typing
						refresh();
						return;
					}

					if (matchesKey(data, Key.escape)) {
						done({ method: METHODS[methodIndex], url: "", body: "", headers: "", cancelled: true });
						return;
					}

					// Open cURL import popup (Ctrl+U for "import URL")
					// Note: Can't use Ctrl+I because it's the same as Tab in terminals
					if (matchesKey(data, Key.ctrl("u"))) {
						showCurlImport = true;
						curlImportError = null;
						curlEditor.setText("");
						refresh();
						return;
					}

					if (matchesKey(data, Key.ctrl("t"))) {
						if (mode === "template" && templateOptions.length > 0) {
							mode = "default";
							customField = "method";
							methodIndex = 0;
							urlEditor.setText("");
							bodyEditor.setText("");
							headersEditor.setText("");
						} else if (mode === "default" && templateOptions.length > 0) {
							mode = "template";
							templateFieldIndex = 0;
							loadTemplate(endpointIndex);
						}
						refresh();
						return;
					}

					if (data === "\r" || data === "\n" || matchesKey(data, Key.enter) || matchesKey(data, Key.ctrl("j")) || matchesKey(data, Key.ctrl("enter"))) {
						submit();
						return;
					}

					if (matchesKey(data, Key.tab)) {
						if (mode === "template") {
							const fields = getTemplateFields();
							templateFieldIndex = (templateFieldIndex + 1) % fields.length;
						} else {
							const method = METHODS[methodIndex];
							const fields: CustomField[] = (method === "GET") 
								? ["method", "url", "headers"]
								: ["method", "url", "body", "headers"];
							const currentIndex = fields.indexOf(customField);
							customField = fields[(currentIndex + 1) % fields.length];
						}
						refresh();
						return;
					}

					if (matchesKey(data, Key.shift("tab"))) {
						if (mode === "template") {
							const fields = getTemplateFields();
							templateFieldIndex = (templateFieldIndex - 1 + fields.length) % fields.length;
						} else {
							const method = METHODS[methodIndex];
							const fields: CustomField[] = (method === "GET") 
								? ["method", "url", "headers"]
								: ["method", "url", "body", "headers"];
							const currentIndex = fields.indexOf(customField);
							customField = fields[(currentIndex - 1 + fields.length) % fields.length];
						}
						refresh();
						return;
					}

					// Handle method/endpoint selection with arrow keys
					if (mode === "template" && getCurrentTemplateField() === "endpoint") {
						if (matchesKey(data, Key.up) || matchesKey(data, Key.left)) {
							endpointIndex = (endpointIndex - 1 + templateOptions.length) % templateOptions.length;
							loadTemplate(endpointIndex);
							refresh();
							return;
						}
						if (matchesKey(data, Key.down) || matchesKey(data, Key.right)) {
							endpointIndex = (endpointIndex + 1) % templateOptions.length;
							loadTemplate(endpointIndex);
							refresh();
							return;
						}
					}
					
					if (mode === "default" && customField === "method") {
						if (matchesKey(data, Key.left)) {
							methodIndex = (methodIndex - 1 + METHODS.length) % METHODS.length;
							refresh();
							return;
						}
						if (matchesKey(data, Key.right)) {
							methodIndex = (methodIndex + 1) % METHODS.length;
							refresh();
							return;
						}
					}

					// Handle body scrolling in template mode
					if (mode === "template" && getCurrentTemplateField() === "body") {
						const bodyLines = bodyEditor.getText().split("\n");
						const maxScroll = Math.max(0, bodyLines.length - bodyMaxVisible);
						if (matchesKey(data, Key.up)) {
							bodyScrollOffset = Math.max(0, bodyScrollOffset - 1);
							refresh();
							return;
						}
						if (matchesKey(data, Key.down)) {
							bodyScrollOffset = Math.min(maxScroll, bodyScrollOffset + 1);
							refresh();
							return;
						}
						bodyEditor.handleInput(data);
						const newLines = bodyEditor.getText().split("\n");
						const newMaxScroll = Math.max(0, newLines.length - bodyMaxVisible);
						if (bodyScrollOffset > newMaxScroll) {
							bodyScrollOffset = newMaxScroll;
						}
						refresh();
						return;
					}

					// Forward to active editor
					const editor = getActiveEditor();
					if (editor) {
						editor.handleInput(data);
						refresh();
					}
				}

				function render(width: number): string[] {
					if (cachedLines) return cachedLines;

					const lines: string[] = [];
					const boxWidth = Math.min(80, width - 4);
					const innerWidth = boxWidth - 4;
					const method = METHODS[methodIndex];

					// Helper functions for box drawing
					function makeTopBorder(title: string) {
						const titleLen = title.replace(/[^\x20-\x7E]/g, " ").length;
						const remaining = boxWidth - 2 - titleLen;
						return theme.fg("accent", "╭") + theme.fg("accent", theme.bold(title)) + theme.fg("accent", "─".repeat(remaining) + "╮");
					}
					function makeBottomBorder() {
						return theme.fg("accent", "╰" + "─".repeat(boxWidth - 2) + "╯");
					}
					function makeDivider() {
						return theme.fg("accent", "├" + "─".repeat(boxWidth - 2) + "┤");
					}
					function makeRow(content: string) {
						const contentLen = content.replace(/\x1b\[[0-9;]*m/g, "").length;
						const padding = Math.max(0, innerWidth - contentLen);
						return theme.fg("accent", "│ ") + content + " ".repeat(padding) + theme.fg("accent", " │");
					}

					// cURL Import Popup
					if (showCurlImport) {
						lines.push("");
						lines.push(makeTopBorder(" Import cURL "));
						lines.push(makeRow(""));
						lines.push(makeRow(theme.fg("muted", "Paste your cURL command below:")));
						lines.push(makeRow(""));
						
						// Render cURL editor (multi-line)
						const curlLines = curlEditor.render(innerWidth - 2);
						const maxCurlLines = 10;
						for (let i = 0; i < Math.min(curlLines.length, maxCurlLines); i++) {
							lines.push(makeRow("  " + curlLines[i]));
						}
						if (curlLines.length > maxCurlLines) {
							lines.push(makeRow(theme.fg("dim", `  ... ${curlLines.length - maxCurlLines} more lines`)));
						}
						
						// Show error if any
						if (curlImportError) {
							lines.push(makeRow(""));
							lines.push(makeRow(theme.fg("error", "  ✗ " + curlImportError)));
						}
						
						lines.push(makeDivider());
						const importShortcuts = [
							theme.fg("muted", "Ctrl+Enter") + theme.fg("dim", " import"),
							theme.fg("muted", "Esc") + theme.fg("dim", " cancel"),
						];
						lines.push(makeRow(importShortcuts.join("  ")));
						lines.push(makeBottomBorder());
						lines.push("");
						lines.push(theme.fg("dim", "  Supports: curl -X METHOD -H 'Header: value' -d 'body' URL"));
						lines.push("");
						
						cachedLines = lines;
						return lines;
					}

					// Title with tabs
					const templateTab = mode === "template" 
						? theme.bg("selectedBg", theme.fg("text", " Template "))
						: theme.fg("dim", " Template ");
					const defaultTab = mode === "default"
						? theme.bg("selectedBg", theme.fg("text", " Default "))
						: theme.fg("dim", " Default ");
					const title = " Super Curl ";
					
					// Alias the helper functions for cleaner code below
					const topBorder = () => makeTopBorder(title);
					const bottomBorder = makeBottomBorder;
					const divider = makeDivider;
					const row = makeRow;
					
					function fieldLabel(label: string, active: boolean, hint?: string) {
						const labelText = active ? theme.fg("warning", theme.bold(label)) : theme.fg("muted", label);
						if (hint) return labelText + " " + theme.fg("dim", `(${hint})`);
						return labelText;
					}

					lines.push("");
					lines.push(topBorder());
					const tabsContent = defaultTab + "  " + templateTab;
					const tabsHint = theme.fg("dim", "(Ctrl+T)");
					const tabsLen = tabsContent.replace(/\x1b\[[0-9;]*m/g, "").length;
					const hintLen = 8; // "(Ctrl+T)"
					const tabsPadding = Math.max(1, innerWidth - tabsLen - hintLen);
					lines.push(row(tabsContent + " ".repeat(tabsPadding) + tabsHint));
					lines.push(divider());

					if (mode === "template") {
						// Endpoint selector
						const endpointActive = getCurrentTemplateField() === "endpoint";
						lines.push(row(fieldLabel("Endpoint:", endpointActive, "↑↓ to change")));
						
						const maxVisible = 3;
						const startIdx = Math.max(0, endpointIndex - 1);
						const endIdx = Math.min(templateOptions.length, startIdx + maxVisible);
						
						for (let i = startIdx; i < endIdx; i++) {
							const opt = templateOptions[i];
							const isSelected = i === endpointIndex;
							const prefix = isSelected ? (endpointActive ? "▸ " : "› ") : "  ";
							const text = isSelected && endpointActive
								? theme.fg("warning", prefix + opt.label)
								: isSelected
								? theme.fg("text", prefix + opt.label)
								: theme.fg("dim", prefix + opt.label);
							lines.push(row(text));
						}
						
						if (templateOptions.length > maxVisible) {
							lines.push(row(theme.fg("dim", `  (${endpointIndex + 1}/${templateOptions.length})`)));
						}
						lines.push(divider());

						// Custom fields
						const fieldConfigs = getTemplateFieldConfigs();
						const currentField = getCurrentTemplateField();
						
						for (const fieldConfig of fieldConfigs) {
							const fieldActive = currentField === fieldConfig.name;
							const labelText = fieldConfig.label || fieldConfig.name;
							const hint = fieldConfig.hint || (fieldConfig.path ? `→ ${fieldConfig.path}` : undefined);
							lines.push(row(fieldLabel(labelText ? `${labelText}:` : "", fieldActive, hint)));
							
							const editor = getFieldEditor(fieldConfig.name);
							const editorLines = editor.render(innerWidth - 2);
							const editorText = editor.getText().trim();
							const textLineCount = editorText ? editorText.split("\n").length : 0;
							const maxLines = fieldActive ? 5 : 2;
							for (const line of editorLines.slice(0, maxLines)) {
								lines.push(row((fieldActive ? "  " : theme.fg("muted", "  ")) + line));
							}
							// Only show "more" if there's actual text content that's truncated
							if (textLineCount > maxLines) {
								lines.push(row(theme.fg("dim", `    ... ${textLineCount - maxLines} more`)));
							}
							// Add bottom border for the input field
							lines.push(row("  " + theme.fg("dim", "─".repeat(innerWidth - 4))));
							lines.push(divider());
						}

						// Body field (optional, scrollable)
						const bodyActive = currentField === "body";
						const bodyText = bodyEditor.getText();
						if (bodyActive) {
							const bodyLines = bodyEditor.render(innerWidth - 2);
							const totalLines = bodyLines.length;
							const scrollable = totalLines > bodyMaxVisible;
							const scrollHint = scrollable 
								? ` ↑↓ scroll ${bodyScrollOffset + 1}-${Math.min(bodyScrollOffset + bodyMaxVisible, totalLines)}/${totalLines}`
								: "";
							lines.push(row(fieldLabel("Body:", true, "optional, JSON") + theme.fg("dim", scrollHint)));
							const visibleLines = bodyLines.slice(bodyScrollOffset, bodyScrollOffset + bodyMaxVisible);
							for (const line of visibleLines) {
								lines.push(row("  " + line));
							}
						} else {
							const bodyHint = bodyText.trim() ? theme.fg("dim", " (has content)") : "";
							lines.push(row(theme.fg("muted", "  Body") + theme.fg("dim", " optional") + bodyHint));
						}

					} else {
						// CUSTOM MODE
						const methodActive = customField === "method";
						const methodButtons = METHODS.map((m, i) => {
							const isSelected = i === methodIndex;
							if (isSelected && methodActive) {
								return theme.bg("selectedBg", theme.fg("text", ` ${m} `));
							} else if (isSelected) {
								return theme.fg("accent", `[${m}]`);
							} else {
								return theme.fg("dim", ` ${m} `);
							}
						}).join(" ");
						lines.push(row(fieldLabel("Method:", methodActive) + "  " + methodButtons + (methodActive ? theme.fg("dim", "  ←→ change") : "")));
						lines.push(divider());

						const urlActive = customField === "url";
						lines.push(row(fieldLabel("URL:", urlActive, "@endpoint or full URL")));
						const urlLines = urlEditor.render(innerWidth - 2);
						for (const line of urlLines) {
							lines.push(row((urlActive ? "  " : theme.fg("muted", "  ")) + line));
						}

						if (method === "POST" || method === "PUT" || method === "PATCH") {
							lines.push(divider());
							const bodyActive = customField === "body";
							lines.push(row(fieldLabel("Body:", bodyActive, "JSON")));
							const bodyLines = bodyEditor.render(innerWidth - 2);
							const maxLines = bodyActive ? 10 : 3;
							for (const line of bodyLines.slice(0, maxLines)) {
								lines.push(row((bodyActive ? "  " : theme.fg("muted", "  ")) + line));
							}
							if (bodyLines.length > maxLines) {
								lines.push(row(theme.fg("dim", `    ... ${bodyLines.length - maxLines} more`)));
							}
						}

						lines.push(divider());
						const headersActive = customField === "headers";
						lines.push(row(fieldLabel("Headers:", headersActive, "Name: Value")));
						const headerLines = headersEditor.render(innerWidth - 2);
						const maxHeaderLines = headersActive ? 5 : 3;
						for (const line of headerLines.slice(0, maxHeaderLines)) {
							lines.push(row((headersActive ? "  " : theme.fg("muted", "  ")) + line));
						}
					}

					lines.push(bottomBorder());
					lines.push("");
					const shortcuts = [
						theme.fg("muted", "Tab") + theme.fg("dim", " next"),
						theme.fg("muted", "Enter") + theme.fg("dim", " send"),
						theme.fg("muted", "Ctrl+U") + theme.fg("dim", " import cURL"),
						theme.fg("muted", "Esc") + theme.fg("dim", " cancel"),
					];
					lines.push("  " + shortcuts.join(theme.fg("dim", "  •  ")));
					lines.push("");

					cachedLines = lines;
					return lines;
				}

				return { render, invalidate: () => { cachedLines = undefined; }, handleInput };
			});

			if (result.cancelled || !result.url) {
				ctx.ui.notify("Request cancelled", "info");
				return;
			}

			// Parse headers
			const extraHeaders: Record<string, string> = {};
			if (result.headers) {
				for (const line of result.headers.split("\n")) {
					const colonIdx = line.indexOf(":");
					if (colonIdx > 0) {
						const key = line.slice(0, colonIdx).trim();
						const value = line.slice(colonIdx + 1).trim();
						if (key) extraHeaders[key] = value;
					}
				}
			}

			// Build the task for the subagent
			config = loadConfig(ctx.cwd);
			
			let resolvedUrl = result.url;
			let endpoint: EndpointConfig | undefined;
			
			if (resolvedUrl.startsWith("@")) {
				const endpointName = resolvedUrl.slice(1);
				endpoint = config.endpoints?.find((e) => e.name === endpointName);
			}

			const method = endpoint?.method || result.method;
			let task = `${method} ${result.url}`;
			
			if (result.body) {
				task += ` with body ${result.body}`;
			}
			
			const headerEntries = Object.entries(extraHeaders);
			if (headerEntries.length > 0) {
				task += ` with headers: ${headerEntries.map(([k, v]) => `${k}: ${v}`).join(", ")}`;
			}

			// Save to history
			addToHistory({
				method: method,
				url: result.url,
				body: result.body || undefined,
				headers: Object.keys(extraHeaders).length > 0 ? extraHeaders : undefined,
				endpoint: result.endpoint,
			});

			// Delegate to api-tester subagent
			pi.sendUserMessage(`Use subagent api-tester to test: ${task}`);
		},
	});

	// Log command - captures logs after subagent request completes
	pi.registerCommand("scurl-log", {
		description: "Capture logs from last request (uses customLogging config)",
		handler: async (_args, ctx) => {
			config = loadConfig(ctx.cwd);

			// Check if customLogging is configured
			if (!config.customLogging?.enabled) {
				ctx.ui.notify("customLogging not enabled in .pi-super-curl/config.json", "error");
				return;
			}

			if (!config.customLogging.outputDir) {
				ctx.ui.notify("customLogging.outputDir not configured", "error");
				return;
			}

			if (!config.customLogging.logs || Object.keys(config.customLogging.logs).length === 0) {
				ctx.ui.notify("customLogging.logs not configured", "error");
				return;
			}

			// Resolve output directory
			const baseOutputDir = config.customLogging.outputDir.startsWith("~")
				? path.join(os.homedir(), config.customLogging.outputDir.slice(1))
				: path.resolve(ctx.cwd, config.customLogging.outputDir);

			// Create timestamp-based directory
			const timestamp = Date.now();
			const outputDir = path.join(baseOutputDir, String(timestamp));

			// Ensure directories exist
			if (!fs.existsSync(outputDir)) {
				fs.mkdirSync(outputDir, { recursive: true });
			}

			// Copy all configured log files
			const copiedLogs: string[] = [];
			const missingLogs: string[] = [];

			for (const [name, logPath] of Object.entries(config.customLogging.logs)) {
				// Resolve path (absolute or relative to cwd)
				const src = path.isAbsolute(logPath)
					? logPath
					: path.resolve(ctx.cwd, logPath);

				const destFilename = `${name}.txt`;
				const dest = path.join(outputDir, destFilename);

				if (fs.existsSync(src)) {
					try {
						fs.copyFileSync(src, dest);
						copiedLogs.push(destFilename);
					} catch (err) {
						missingLogs.push(`${name} (copy failed)`);
					}
				} else {
					missingLogs.push(`${name} (not found)`);
				}
			}

			// Run post-processing script if configured
			// Scripts are resolved relative to configDir (.pi-super-curl/ directory)
			let postScriptResult = "";
			if (config.customLogging.postScript) {
				const scriptPath = path.isAbsolute(config.customLogging.postScript)
					? config.customLogging.postScript
					: path.resolve(configDir, config.customLogging.postScript);

				if (fs.existsSync(scriptPath)) {
					// Show processing indicator while script runs
					ctx.ui.notify("Processing... (downloading from GCS)", "info");
					
					try {
						const { execSync } = require("child_process");
						// Pass output directory as argument, run from cwd
						execSync(`"${scriptPath}" "${outputDir}"`, {
							cwd: ctx.cwd,
							stdio: "pipe",
							timeout: 120000, // 2 minute timeout for GCS downloads
						});
						postScriptResult = "\n  Post-script: ✓ executed";
					} catch (err: any) {
						// Check if it's "already processed" (exit code 2)
						if (err?.status === 2) {
							ctx.ui.notify(
								"⚠️ Log already processed\n" +
								"  This request was already logged.\n" +
								"  Run a new /scurl request first.",
								"warning"
							);
							return; // Exit early, don't show success message
						}
						postScriptResult = `\n  Post-script: ✗ ${err instanceof Error ? err.message : "failed"}`;
					}
				} else {
					postScriptResult = `\n  Post-script: ✗ not found at ${scriptPath}`;
				}
			}

			// Show result
			if (copiedLogs.length > 0) {
				ctx.ui.notify(
					`✓ Logs saved to ${outputDir}\n` +
					`  Files: ${copiedLogs.join(", ")}` +
					(missingLogs.length > 0 ? `\n  Missing: ${missingLogs.join(", ")}` : "") +
					postScriptResult,
					"success"
				);
			} else {
				ctx.ui.notify(
					`✗ No logs found\n` +
					`  Missing: ${missingLogs.join(", ")}`,
					"error"
				);
			}
		},
	});

	// History browser result
	interface HistoryBrowserResult {
		action: "replay" | "delete" | "clear" | "cancel";
		entry?: HistoryEntry;
	}

	// History browser command
	pi.registerCommand("scurl-history", {
		description: "Browse and replay request history",
		handler: async (_args, ctx) => {
			const history = loadHistory();

			if (history.length === 0) {
				ctx.ui.notify("No request history yet. Use /scurl to make requests.", "info");
				return;
			}

			const result = await ctx.ui.custom<HistoryBrowserResult>((tui, theme, _kb, done) => {
				let selectedIndex = 0;
				let scrollOffset = 0;
				const maxVisible = 12;
				let showDetails = false;
				let confirmClear = false;
				let cachedLines: string[] | undefined;

				function refresh() {
					cachedLines = undefined;
					tui.requestRender();
				}

				function handleInput(data: string) {
					// Cancel confirmation mode
					if (confirmClear) {
						if (data.toLowerCase() === "y") {
							clearHistory();
							done({ action: "clear" });
							return;
						}
						confirmClear = false;
						refresh();
						return;
					}

					if (matchesKey(data, Key.escape)) {
						if (showDetails) {
							showDetails = false;
							refresh();
							return;
						}
						done({ action: "cancel" });
						return;
					}

					if (matchesKey(data, Key.enter)) {
						const entry = history[selectedIndex];
						if (entry) {
							done({ action: "replay", entry });
						}
						return;
					}

					// Toggle details view
					if (data === "d" || data === "D") {
						showDetails = !showDetails;
						refresh();
						return;
					}

					// Delete entry
					if (data === "x" || data === "X" || matchesKey(data, Key.delete) || matchesKey(data, Key.backspace)) {
						const entry = history[selectedIndex];
						if (entry) {
							deleteFromHistory(entry.id);
							history.splice(selectedIndex, 1);
							if (selectedIndex >= history.length) {
								selectedIndex = Math.max(0, history.length - 1);
							}
							if (history.length === 0) {
								done({ action: "cancel" });
								return;
							}
							refresh();
						}
						return;
					}

					// Clear all
					if (data === "c" || data === "C") {
						confirmClear = true;
						refresh();
						return;
					}

					// Navigation
					if (matchesKey(data, Key.up) || data === "k") {
						selectedIndex = Math.max(0, selectedIndex - 1);
						// Adjust scroll
						if (selectedIndex < scrollOffset) {
							scrollOffset = selectedIndex;
						}
						refresh();
						return;
					}

					if (matchesKey(data, Key.down) || data === "j") {
						selectedIndex = Math.min(history.length - 1, selectedIndex + 1);
						// Adjust scroll
						if (selectedIndex >= scrollOffset + maxVisible) {
							scrollOffset = selectedIndex - maxVisible + 1;
						}
						refresh();
						return;
					}

					// Page navigation
					if (matchesKey(data, Key.pageUp)) {
						selectedIndex = Math.max(0, selectedIndex - maxVisible);
						scrollOffset = Math.max(0, scrollOffset - maxVisible);
						refresh();
						return;
					}

					if (matchesKey(data, Key.pageDown)) {
						selectedIndex = Math.min(history.length - 1, selectedIndex + maxVisible);
						scrollOffset = Math.min(Math.max(0, history.length - maxVisible), scrollOffset + maxVisible);
						refresh();
						return;
					}

					// Home/End
					if (matchesKey(data, Key.home)) {
						selectedIndex = 0;
						scrollOffset = 0;
						refresh();
						return;
					}

					if (matchesKey(data, Key.end)) {
						selectedIndex = history.length - 1;
						scrollOffset = Math.max(0, history.length - maxVisible);
						refresh();
						return;
					}
				}

				function render(width: number): string[] {
					if (cachedLines) return cachedLines;

					const lines: string[] = [];
					const boxWidth = Math.min(90, width - 4);
					const innerWidth = boxWidth - 4;

					function topBorder(title: string) {
						const titleLen = title.replace(/[^\x20-\x7E]/g, " ").length;
						const remaining = boxWidth - 2 - titleLen;
						return theme.fg("accent", "╭") + theme.fg("accent", theme.bold(title)) + theme.fg("accent", "─".repeat(remaining) + "╮");
					}
					function bottomBorder() {
						return theme.fg("accent", "╰" + "─".repeat(boxWidth - 2) + "╯");
					}
					function divider() {
						return theme.fg("accent", "├" + "─".repeat(boxWidth - 2) + "┤");
					}
					function row(content: string) {
						const contentLen = content.replace(/\x1b\[[0-9;]*m/g, "").length;
						const padding = Math.max(0, innerWidth - contentLen);
						return theme.fg("accent", "│ ") + content + " ".repeat(padding) + theme.fg("accent", " │");
					}

					lines.push("");
					lines.push(topBorder(" Request History "));

					// Header
					const countInfo = theme.fg("dim", `(${history.length} request${history.length !== 1 ? "s" : ""})`);
					lines.push(row(countInfo));
					lines.push(divider());

					// Confirmation dialog
					if (confirmClear) {
						lines.push(row(""));
						lines.push(row(theme.fg("warning", "  Clear all history? ") + theme.fg("dim", "(y/n)")));
						lines.push(row(""));
						lines.push(bottomBorder());
						cachedLines = lines;
						return lines;
					}

					// Details view
					if (showDetails && history[selectedIndex]) {
						const entry = history[selectedIndex];
						const date = new Date(entry.timestamp);
						
						lines.push(row(theme.fg("text", theme.bold("  " + entry.method + " ") + entry.url)));
						lines.push(row(""));
						lines.push(row(theme.fg("muted", "  Date: ") + date.toLocaleString()));
						
						if (entry.endpoint) {
							lines.push(row(theme.fg("muted", "  Endpoint: ") + "@" + entry.endpoint));
						}
						
						if (entry.headers && Object.keys(entry.headers).length > 0) {
							lines.push(row(""));
							lines.push(row(theme.fg("muted", "  Headers:")));
							for (const [k, v] of Object.entries(entry.headers)) {
								const headerLine = `    ${k}: ${v}`;
								const truncated = headerLine.length > innerWidth - 2 
									? headerLine.slice(0, innerWidth - 5) + "..." 
									: headerLine;
								lines.push(row(theme.fg("dim", truncated)));
							}
						}
						
						if (entry.body) {
							lines.push(row(""));
							lines.push(row(theme.fg("muted", "  Body:")));
							try {
								const parsed = JSON.parse(entry.body);
								const pretty = JSON.stringify(parsed, null, 2).split("\n");
								for (const line of pretty.slice(0, 10)) {
									const truncated = line.length > innerWidth - 4 
										? line.slice(0, innerWidth - 7) + "..." 
										: line;
									lines.push(row(theme.fg("dim", "    " + truncated)));
								}
								if (pretty.length > 10) {
									lines.push(row(theme.fg("dim", `    ... ${pretty.length - 10} more lines`)));
								}
							} catch {
								const truncated = entry.body.length > innerWidth - 4
									? entry.body.slice(0, innerWidth - 7) + "..."
									: entry.body;
								lines.push(row(theme.fg("dim", "    " + truncated)));
							}
						}
						
						lines.push(divider());
						lines.push(row(
							theme.fg("muted", "Enter") + theme.fg("dim", " replay  ") +
							theme.fg("muted", "d") + theme.fg("dim", " back  ") +
							theme.fg("muted", "Esc") + theme.fg("dim", " close")
						));
						lines.push(bottomBorder());
						lines.push("");
						
						cachedLines = lines;
						return lines;
					}

					// List view
					const visibleHistory = history.slice(scrollOffset, scrollOffset + maxVisible);
					
					for (let i = 0; i < visibleHistory.length; i++) {
						const entry = visibleHistory[i];
						const actualIndex = scrollOffset + i;
						const isSelected = actualIndex === selectedIndex;
						
						const date = new Date(entry.timestamp);
						const timeStr = date.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
						const dateStr = date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
						
						// Method with color
						const methodColors: Record<string, string> = {
							GET: "success",
							POST: "accent",
							PUT: "warning",
							PATCH: "warning",
							DELETE: "error",
						};
						const methodColor = methodColors[entry.method] || "text";
						const methodStr = theme.fg(methodColor as any, entry.method.padEnd(6));
						
						// URL (truncate if needed)
						const url = entry.endpoint ? `@${entry.endpoint}` : entry.url;
						const maxUrlLen = innerWidth - 30;
						const truncatedUrl = url.length > maxUrlLen ? url.slice(0, maxUrlLen - 3) + "..." : url;
						
						// Timestamp
						const timestamp = theme.fg("dim", `${dateStr} ${timeStr}`);
						
						const prefix = isSelected ? theme.fg("warning", "▸ ") : "  ";
						const urlText = isSelected ? theme.fg("text", truncatedUrl) : theme.fg("muted", truncatedUrl);
						
						lines.push(row(prefix + methodStr + " " + urlText.padEnd(maxUrlLen) + "  " + timestamp));
					}

					// Scroll indicator
					if (history.length > maxVisible) {
						const scrollInfo = `${scrollOffset + 1}-${Math.min(scrollOffset + maxVisible, history.length)} of ${history.length}`;
						lines.push(row(theme.fg("dim", "  " + scrollInfo)));
					}

					lines.push(divider());
					
					// Shortcuts
					const shortcuts = [
						theme.fg("muted", "↑↓") + theme.fg("dim", " nav"),
						theme.fg("muted", "Enter") + theme.fg("dim", " replay"),
						theme.fg("muted", "d") + theme.fg("dim", " details"),
						theme.fg("muted", "x") + theme.fg("dim", " delete"),
						theme.fg("muted", "c") + theme.fg("dim", " clear"),
						theme.fg("muted", "Esc") + theme.fg("dim", " close"),
					];
					lines.push(row(shortcuts.join("  ")));
					lines.push(bottomBorder());
					lines.push("");

					cachedLines = lines;
					return lines;
				}

				return { render, invalidate: () => { cachedLines = undefined; }, handleInput };
			});

			if (result.action === "cancel") {
				return;
			}

			if (result.action === "clear") {
				ctx.ui.notify("History cleared", "info");
				return;
			}

			if (result.action === "replay" && result.entry) {
				const entry = result.entry;
				config = loadConfig(ctx.cwd);

				// Build the task for the subagent
				let task = `${entry.method} ${entry.url}`;
				
				if (entry.body) {
					task += ` with body ${entry.body}`;
				}
				
				if (entry.headers && Object.keys(entry.headers).length > 0) {
					const headerEntries = Object.entries(entry.headers);
					task += ` with headers: ${headerEntries.map(([k, v]) => `${k}: ${v}`).join(", ")}`;
				}

				// Save new history entry for the replay
				addToHistory({
					method: entry.method,
					url: entry.url,
					body: entry.body,
					headers: entry.headers,
					endpoint: entry.endpoint,
				});

				// Delegate to api-tester subagent
				pi.sendUserMessage(`Use subagent api-tester to test: ${task}`);
			}
		},
	});

	// Input transformer for natural language
	pi.on("input", async (event) => {
		const text = event.text.trim();
		
		const patterns = [
			/^use\s+send-request\s+skill\s+(?:with|to)\s+(.+)$/i,
			/^use\s+send-request\s+(?:with|to)\s+(.+)$/i,
			/^send-request\s+skill[:\s]+(.+)$/i,
		];

		for (const pattern of patterns) {
			const match = text.match(pattern);
			if (match) {
				return { action: "transform" as const, text: `/skill:send-request ${match[1].trim()}` };
			}
		}

		return { action: "continue" as const };
	});

	// Load config on session start
	pi.on("session_start", async (_event, ctx) => {
		config = loadConfig(ctx.cwd);
		if (config.baseUrl || config.endpoints?.length) {
			ctx.ui.setStatus("super-curl", "🌐");
		}
	});
}
