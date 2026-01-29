/**
 * Super Curl - HTTP Request Extension for Pi
 *
 * A Postman-like tool for sending HTTP requests with:
 * - Interactive UI popup for building requests
 * - Environment-based configuration
 * - Automatic authentication (Bearer tokens, API keys, JWT generation)
 * - Response saving to configurable directory
 * - Template variables ({{uuid}}, {{uuidv7}}, {{env.VAR}}, {{timestamp}})
 *
 * Usage:
 *   pi -e ~/Desktop/super-curl
 *
 * Commands:
 *   /request - Open Postman-like request builder UI
 *   /curl [METHOD] URL - Quick request
 *   /endpoints - List configured endpoints
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
}

// Template: pre-configured request for quick access
interface TemplateConfig {
	name: string;
	description?: string;
	endpoint: string; // Reference to @endpoint name
	body?: Record<string, unknown>; // Overrides/merges with endpoint's defaultBody
	headers?: Record<string, string>; // Extra headers
	fields?: TemplateFieldConfig[]; // User-defined input fields
}

// Parsed SSE result for Morphic-style responses
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

interface SuperCurlConfig {
	baseUrl?: string;
	auth?: AuthConfig;
	headers?: Record<string, string>;
	outputDir?: string;
	endpoints?: EndpointConfig[];
	templates?: TemplateConfig[]; // Pre-configured request templates
	timeout?: number;
	envFile?: string; // Path to .env file (relative to project or absolute)
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

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;

export default function superCurlExtension(pi: ExtensionAPI) {
	let config: SuperCurlConfig = {};

	// Load configuration
	function loadConfig(cwd: string): SuperCurlConfig {
		const configPaths = [
			path.join(cwd, ".super-curl.json"),
			path.join(os.homedir(), ".super-curl.json"),
		];

		for (const configPath of configPaths) {
			if (fs.existsSync(configPath)) {
				try {
					const content = fs.readFileSync(configPath, "utf-8");
					const cfg = JSON.parse(content) as SuperCurlConfig;
					
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

	// Parse SSE stream for Morphic-style responses
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

	// Get output directory
	function getOutputDir(cwd: string): string {
		if (config.outputDir) {
			const dir = config.outputDir.startsWith("~")
				? path.join(os.homedir(), config.outputDir.slice(1))
				: path.resolve(cwd, config.outputDir);
			if (!fs.existsSync(dir)) {
				fs.mkdirSync(dir, { recursive: true });
			}
			return dir;
		}
		return path.join(os.homedir(), "Desktop", "api-responses");
	}

	// Save response to file
	function saveOutput(cwd: string, response: string, contentType: string | null, url: string): string {
		const outputDir = getOutputDir(cwd);
		if (!fs.existsSync(outputDir)) {
			fs.mkdirSync(outputDir, { recursive: true });
		}

		const timestamp = Date.now();
		let urlPath = "";
		try {
			urlPath = new URL(url).pathname.replace(/\//g, "_").slice(0, 50);
		} catch {
			urlPath = "_response";
		}

		let extension = "txt";
		if (contentType?.includes("application/json")) extension = "json";
		else if (contentType?.includes("text/html")) extension = "html";

		const filename = `response_${timestamp}${urlPath}.${extension}`;
		const filepath = path.join(outputDir, filename);
		fs.writeFileSync(filepath, response);
		return filepath;
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
		endpoint?: EndpointConfig;
	}

	function logGeneration(params: GenerationLogParams): string[] {
		const outputDir = config.outputDir 
			? path.resolve(params.cwd, config.outputDir.replace(/^~/, os.homedir()))
			: null;
		
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
			copyDebugLogs(params.cwd, errorDir, params.endpoint);
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
				copyDebugLogs(params.cwd, outDir, params.endpoint);
			}

			loggedPaths.push(outDir);
		}

		return loggedPaths;
	}

	function copyDebugLogs(cwd: string, destDir: string, endpoint?: EndpointConfig): void {
		if (!endpoint?.debug) return;

		// Copy workflow logs
		if (endpoint.debug.workflowLogs) {
			const src = path.resolve(cwd, endpoint.debug.workflowLogs);
			if (fs.existsSync(src)) {
				const dest = path.join(destDir, "workflow-logs.txt");
				fs.copyFileSync(src, dest);
			}
		}

		// Copy backend logs
		if (endpoint.debug.backendLogs) {
			const src = path.resolve(cwd, endpoint.debug.backendLogs);
			if (fs.existsSync(src)) {
				const dest = path.join(destDir, "backend-logs.txt");
				fs.copyFileSync(src, dest);
			}
		}
	}

	// Register /scurl command - Super Curl request builder
	pi.registerCommand("scurl", {
		description: "Open Super Curl request builder (Ctrl+T for templates)",
		handler: async (_args, ctx) => {
			config = loadConfig(ctx.cwd);

			// Build template list for template mode
			// Templates are preferred, but fall back to endpoints if no templates defined
			interface TemplateOption {
				name: string;
				label: string;
				description?: string;
				endpoint?: EndpointConfig;
				bodyOverrides?: Record<string, unknown>;
				extraHeaders?: Record<string, string>;
				fields?: TemplateFieldConfig[];
			}
			
			const templateOptions: TemplateOption[] = [];
			
			if (config.templates && config.templates.length > 0) {
				// Use configured templates
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
					});
				}
			} else {
				// Fall back to endpoints as templates
				for (const ep of config.endpoints || []) {
					templateOptions.push({
						name: ep.name,
						label: `@${ep.name} (${ep.method || "GET"})`,
						endpoint: ep,
					});
				}
			}

			const result = await ctx.ui.custom<RequestBuilderResult>((tui, theme, _kb, done) => {
				// Mode: "template" (quick endpoint + prompt) or "default" (full postman)
				let mode: "template" | "default" = "default";
				
				// State for template mode
				let endpointIndex = 0;
				
				// State for custom mode
				let methodIndex = 0; // GET by default
				
				// Dynamic field editors for template mode (keyed by field name)
				let fieldEditors: Map<string, Editor> = new Map();
				
				// Active field depends on mode
				// For template mode: "endpoint" | field.name | "body" | "headers"
				let templateFieldIndex = 0; // Index into getTemplateFields() array
				type CustomField = "method" | "url" | "body" | "headers";
				let customField: CustomField = "method";
				
				let cachedLines: string[] | undefined;

				// Editor theme
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

				// Editors
				const urlEditor = new Editor(tui, editorTheme);
				const bodyEditor = new Editor(tui, editorTheme);
				const headersEditor = new Editor(tui, editorTheme);

				// Default field shown when template has no custom fields
				const defaultPromptField: TemplateFieldConfig = {
					name: "prompt",
					label: "",  // No label
					path: "generation_params.positive_prompt",
				};
				
				// Get the list of navigable fields for current template
				// Returns: ["endpoint", ...field names..., "body", "headers"]
				function getTemplateFields(): string[] {
					const fields = ["endpoint"];
					const tpl = templateOptions[endpointIndex];
					if (tpl?.fields && tpl.fields.length > 0) {
						for (const f of tpl.fields) {
							fields.push(f.name);
						}
					} else {
						// Default: show prompt field
						fields.push("prompt");
					}
					fields.push("body", "headers");
					return fields;
				}
				
				// Get field configs for current template (custom or default)
				function getTemplateFieldConfigs(): TemplateFieldConfig[] {
					const tpl = templateOptions[endpointIndex];
					if (tpl?.fields && tpl.fields.length > 0) {
						return tpl.fields;
					}
					return [defaultPromptField];
				}
				
				// Get current template field name
				function getCurrentTemplateField(): string {
					const fields = getTemplateFields();
					return fields[templateFieldIndex] || "endpoint";
				}
				
				// Get or create editor for a field
				function getFieldEditor(fieldName: string): Editor {
					if (!fieldEditors.has(fieldName)) {
						const editor = new Editor(tui, editorTheme);
						// Set default value if configured
						const tpl = templateOptions[endpointIndex];
						const fieldConfig = tpl?.fields?.find(f => f.name === fieldName);
						if (fieldConfig?.default) {
							editor.setText(fieldConfig.default);
						}
						fieldEditors.set(fieldName, editor);
					}
					return fieldEditors.get(fieldName)!;
				}

				// Custom mode: all fields start empty (no pre-population)

				// Load template (merges endpoint defaultBody with template overrides)
				function loadTemplate(idx: number) {
					if (idx < 0 || idx >= templateOptions.length) return;
					const opt = templateOptions[idx];
					if (opt.endpoint) {
						const methodIdx = METHODS.indexOf(opt.endpoint.method || "GET");
						if (methodIdx >= 0) methodIndex = methodIdx;
						
						// Merge endpoint defaultBody with template bodyOverrides
						let body: Record<string, unknown> = {};
						if (opt.endpoint.defaultBody) {
							body = JSON.parse(JSON.stringify(opt.endpoint.defaultBody)); // Deep clone
						}
						if (opt.bodyOverrides) {
							// Deep merge bodyOverrides into body
							body = deepMerge(body, opt.bodyOverrides);
						}
						
						if (Object.keys(body).length > 0) {
							bodyEditor.setText(JSON.stringify(body, null, 2));
						} else {
							bodyEditor.setText("");
						}
						
						// Set extra headers if defined
						if (opt.extraHeaders) {
							const headerLines = Object.entries(opt.extraHeaders)
								.map(([k, v]) => `${k}: ${v}`)
								.join("\n");
							headersEditor.setText(headerLines);
						} else {
							headersEditor.setText("");
						}
						
						// Reset field editors and set defaults
						fieldEditors = new Map();
						const fieldsToSetup = (opt.fields && opt.fields.length > 0) ? opt.fields : [defaultPromptField];
						for (const f of fieldsToSetup) {
							const editor = new Editor(tui, editorTheme);
							if (f.default) {
								editor.setText(f.default);
							}
							fieldEditors.set(f.name, editor);
						}
						
						// Reset field index to endpoint
						templateFieldIndex = 0;
					}
				}
				
				// Deep merge helper
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

				// Template is loaded when user switches to template mode via Ctrl+T

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
						// It's a custom field
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

				// Set value at a JSON path (e.g., "generation_params.positive_prompt")
				function setAtPath(obj: Record<string, unknown>, pathStr: string, value: unknown): void {
					const parts = pathStr.split(".");
					let current = obj;
					for (let i = 0; i < parts.length - 1; i++) {
						const part = parts[i];
						if (!(part in current) || typeof current[part] !== "object") {
							current[part] = {};
						}
						current = current[part] as Record<string, unknown>;
					}
					current[parts[parts.length - 1]] = value;
				}

				function buildFinalBody(): string {
					const bodyText = bodyEditor.getText().trim();
					
					if (mode === "template") {
						const fieldConfigs = getTemplateFieldConfigs();
						
						try {
							const body = bodyText ? JSON.parse(bodyText) : {};
							
							// Inject each field value at its configured path
							for (const fieldConfig of fieldConfigs) {
								if (!fieldConfig.path) continue;
								const editor = fieldEditors.get(fieldConfig.name);
								const value = editor?.getText().trim() || "";
								if (value) {
									setAtPath(body, fieldConfig.path, value);
								}
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
						// Return the endpoint name (not template name)
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
					// Escape to cancel
					if (matchesKey(data, Key.escape)) {
						done({
							method: METHODS[methodIndex],
							url: "",
							body: "",
							headers: "",
							cancelled: true,
						});
						return;
					}

					// Ctrl+T to toggle mode
					if (matchesKey(data, Key.ctrl("t"))) {
						if (mode === "template" && templateOptions.length > 0) {
							mode = "default";
							customField = "method";
							// Reset all fields to empty for default mode
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

					// Enter or Ctrl+Enter to send (check raw \r and \n too)
					if (data === "\r" || data === "\n" || matchesKey(data, Key.enter) || matchesKey(data, Key.ctrl("j")) || matchesKey(data, Key.ctrl("enter"))) {
						submit();
						return;
					}

					// Tab to switch fields
					if (matchesKey(data, Key.tab)) {
						if (mode === "template") {
							const fields = getTemplateFields();
							templateFieldIndex = (templateFieldIndex + 1) % fields.length;
						} else {
							// Skip body field for GET method
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

					// Shift+Tab to switch fields backwards
					if (matchesKey(data, Key.shift("tab"))) {
						if (mode === "template") {
							const fields = getTemplateFields();
							templateFieldIndex = (templateFieldIndex - 1 + fields.length) % fields.length;
						} else {
							// Skip body field for GET method
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

					// Handle selector fields
					if (mode === "template" && getCurrentTemplateField() === "endpoint") {
						if (matchesKey(data, Key.left) || matchesKey(data, Key.up)) {
							endpointIndex = (endpointIndex - 1 + templateOptions.length) % templateOptions.length;
							loadTemplate(endpointIndex);
							refresh();
							return;
						}
						if (matchesKey(data, Key.right) || matchesKey(data, Key.down)) {
							endpointIndex = (endpointIndex + 1) % templateOptions.length;
							loadTemplate(endpointIndex);
							refresh();
							return;
						}
						const num = parseInt(data);
						if (num >= 1 && num <= templateOptions.length) {
							endpointIndex = num - 1;
							loadTemplate(endpointIndex);
							refresh();
							return;
						}
						return;
					}

					if (mode === "default" && customField === "method") {
						if (matchesKey(data, Key.left) || matchesKey(data, Key.up)) {
							methodIndex = (methodIndex - 1 + METHODS.length) % METHODS.length;
							refresh();
							return;
						}
						if (matchesKey(data, Key.right) || matchesKey(data, Key.down)) {
							methodIndex = (methodIndex + 1) % METHODS.length;
							refresh();
							return;
						}
						const num = parseInt(data);
						if (num >= 1 && num <= METHODS.length) {
							methodIndex = num - 1;
							refresh();
							return;
						}
						return;
					}

					// Pass to active editor
					const editor = getActiveEditor();
					if (editor) {
						editor.handleInput(data);
						refresh();
					}
				}

				function render(width: number): string[] {
					if (cachedLines) return cachedLines;

					const lines: string[] = [];
					const boxWidth = Math.min(width - 6, 110);
					const method = METHODS[methodIndex];

					// Strip ANSI codes to get visible length
					const visibleLength = (str: string) => str.replace(/\x1b\[[0-9;]*m/g, "").length;
					
					// Truncate string to max visible length (accounting for ANSI codes)
					const truncate = (str: string, maxLen: number): string => {
						const stripped = str.replace(/\x1b\[[0-9;]*m/g, "");
						if (stripped.length <= maxLen) return str;
						
						// Need to truncate - walk through and count visible chars
						let visible = 0;
						let result = "";
						let i = 0;
						while (i < str.length && visible < maxLen - 1) {
							if (str[i] === "\x1b") {
								// ANSI escape - copy until 'm'
								const end = str.indexOf("m", i);
								if (end !== -1) {
									result += str.slice(i, end + 1);
									i = end + 1;
									continue;
								}
							}
							result += str[i];
							visible++;
							i++;
						}
						return result + "…";
					};
					
					// Pad string to width accounting for ANSI codes
					const padEnd = (str: string, len: number) => {
						const visible = visibleLength(str);
						const padding = Math.max(0, len - visible);
						return str + " ".repeat(padding);
					};

					// Box drawing helpers (default terminal color)
					const innerWidth = boxWidth - 1; // -1 for leading space in row
					const topBorder = () => `  ┌${"─".repeat(boxWidth)}┐`;
					const bottomBorder = () => `  └${"─".repeat(boxWidth)}┘`;
					const divider = () => `  ├${"─".repeat(boxWidth)}┤`;
					const row = (content: string) => {
						const padded = " " + truncate(content, innerWidth);
						return `  │${padEnd(padded, boxWidth)}│`;
					};

					// Helper for field label with active indicator
					const fieldLabel = (label: string, active: boolean, hint?: string) => {
						const indicator = active ? theme.fg("accent", "▸") : " ";
						const labelStyled = active ? theme.fg("accent", theme.bold(label)) : theme.fg("muted", label);
						const hintText = hint ? theme.fg("dim", `  ${hint}`) : "";
						return `${indicator} ${labelStyled}${hintText}`;
					};

					// Title
					lines.push("");
					lines.push(topBorder());
					const modeIcon = mode === "template" ? "◈" : "◉";
					const modeLabel = mode === "template" ? "Template" : "Default";
					lines.push(row(theme.fg("accent", theme.bold(`${modeIcon} Super Curl · ${modeLabel}`))));
					
					if (templateOptions.length > 0) {
						const switchTo = mode === "template" ? "default" : "template";
						lines.push(row(theme.fg("dim", `Ctrl+T → switch to ${switchTo}`)));
					}
					lines.push(divider());

					if (mode === "template") {
						// TEMPLATE MODE
						const currentEndpoint = templateOptions[endpointIndex];
						const currentField = getCurrentTemplateField();
						const epActive = currentField === "endpoint";
						
						// Endpoint selector
						let epDisplay = "";
						if (epActive) {
							epDisplay = theme.bg("selectedBg", theme.fg("text", ` ${currentEndpoint?.label || "none"} `));
							epDisplay += theme.fg("dim", "  ←→ change");
						} else {
							epDisplay = theme.fg("text", currentEndpoint?.label || "none");
						}
						lines.push(row(fieldLabel("Endpoint:", epActive) + "  " + epDisplay));
						lines.push(row(theme.fg("dim", `   Method: ${method}`)));
						lines.push(divider());

						// Dynamic fields from template config (or default prompt)
						const tplFields = getTemplateFieldConfigs();
						for (const fieldConfig of tplFields) {
							const isActive = currentField === fieldConfig.name;
							const editor = getFieldEditor(fieldConfig.name);
							
							// Only show label row if label is defined
							if (fieldConfig.label) {
								lines.push(row(fieldLabel(`${fieldConfig.label}:`, isActive, fieldConfig.hint)));
							}
							const fieldLines = editor.render(innerWidth - 2);
							for (const line of fieldLines) {
								lines.push(row((isActive ? "  " : theme.fg("muted", "  ")) + line));
							}
							lines.push(divider());
						}

						// Body field
						const bodyActive = currentField === "body";
						const bodyText = bodyEditor.getText();
						lines.push(row(fieldLabel("Body:", bodyActive, "JSON")));
						if (bodyActive) {
							const bodyLines = bodyEditor.render(innerWidth - 2);
							for (const line of bodyLines.slice(0, 8)) {
								lines.push(row("  " + line));
							}
							if (bodyLines.length > 8) {
								lines.push(row(theme.fg("dim", `    ... ${bodyLines.length - 8} more lines`)));
							}
						} else {
							const preview = bodyText ? bodyText.replace(/\s+/g, " ").slice(0, innerWidth - 8) : "(empty)";
							lines.push(row(theme.fg("dim", "  " + preview)));
						}
						lines.push(divider());

						// Headers field
						const headersActive = currentField === "headers";
						const headersText = headersEditor.getText().trim();
						lines.push(row(fieldLabel("Headers:", headersActive, "optional")));
						if (headersActive) {
							const headerLines = headersEditor.render(innerWidth - 2);
							for (const line of headerLines) {
								lines.push(row("  " + line));
							}
						} else {
							const preview = headersText ? headersText.split("\n")[0] : "(none)";
							lines.push(row(theme.fg("dim", "  " + preview)));
						}

					} else {
						// CUSTOM MODE
						
						// Method selector
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
						lines.push(row(fieldLabel("Method:", methodActive) + "  " + methodButtons));
						lines.push(divider());

						// URL field
						const urlActive = customField === "url";
						lines.push(row(fieldLabel("URL:", urlActive, "@endpoint or full URL")));
						const urlLines = urlEditor.render(innerWidth - 2);
						for (const line of urlLines) {
							lines.push(row((urlActive ? "  " : theme.fg("muted", "  ")) + line));
						}

						// Body field (only for POST/PUT/PATCH)
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

						// Headers field
						lines.push(divider());
						const headersActive = customField === "headers";
						lines.push(row(fieldLabel("Headers:", headersActive, "Name: Value")));
						const headerLines = headersEditor.render(innerWidth - 2);
						const maxHeaderLines = headersActive ? 5 : 3;
						for (const line of headerLines.slice(0, maxHeaderLines)) {
							lines.push(row((headersActive ? "  " : theme.fg("muted", "  ")) + line));
						}
					}

					// Bottom border
					lines.push(bottomBorder());
					
					// Footer shortcuts
					lines.push("");
					const shortcuts = [
						theme.fg("muted", "Tab") + theme.fg("dim", " next"),
						theme.fg("muted", "Enter") + theme.fg("dim", " send"),
						theme.fg("muted", "Esc") + theme.fg("dim", " cancel"),
					];
					lines.push("  " + shortcuts.join(theme.fg("dim", "  •  ")));
					lines.push("");

					cachedLines = lines;
					return lines;
				}

				return {
					render,
					invalidate: () => { cachedLines = undefined; },
					handleInput,
				};
			});

			if (result.cancelled || !result.url) {
				ctx.ui.notify("Request cancelled", "info");
				return;
			}

			// Build the request message for the LLM
			let message = `Use send_request to ${result.method} ${result.url}`;
			if (result.body) {
				message += ` with body ${result.body}`;
			}
			if (result.headers) {
				message += ` with headers: ${result.headers}`;
			}

			// Send as user message to trigger the agent
			pi.sendUserMessage(message);
		},
	});

	// Register send_request tool
	pi.registerTool({
		name: "send_request",
		label: "HTTP Request",
		description: `Send an HTTP request. Supports GET, POST, PUT, PATCH, DELETE methods.
Configuration loaded from .super-curl.json (project root or home directory).
Features: automatic auth, named endpoints (@name), response saving.`,
		parameters: Type.Object({
			method: StringEnum(["GET", "POST", "PUT", "PATCH", "DELETE"] as const, {
				description: "HTTP method",
				default: "GET",
			}),
			url: Type.String({
				description: "Full URL, path (uses baseUrl from config), or @endpoint name",
			}),
			headers: Type.Optional(Type.Record(Type.String(), Type.String(), {
				description: "Additional headers",
			})),
			body: Type.Optional(Type.String({
				description: "Request body (JSON string)",
			})),
			save: Type.Optional(Type.Boolean({
				description: "Save response to output directory",
				default: false,
			})),
		}),

		async execute(_toolCallId, params, onUpdate, ctx, signal) {
			const { method = "GET", headers: extraHeaders = {}, body, save = false } = params;
			let { url } = params;
			const startTime = Date.now();

			config = loadConfig(ctx.cwd);

			// Handle named endpoints
			let endpoint: EndpointConfig | undefined;
			if (url.startsWith("@")) {
				const endpointName = url.slice(1);
				endpoint = config.endpoints?.find((e) => e.name === endpointName);
				if (!endpoint) {
					const available = config.endpoints?.map((e) => e.name).join(", ") || "none";
					return {
						content: [{ type: "text", text: `Endpoint "@${endpointName}" not found. Available: ${available}` }],
						details: { error: true },
						isError: true,
					};
				}
				url = endpoint.url;
			}

			// Build full URL (resolve templates in baseUrl first)
			if (!url.startsWith("http://") && !url.startsWith("https://")) {
				if (config.baseUrl) {
					const resolvedBaseUrl = resolveTemplates(config.baseUrl);
					url = `${resolvedBaseUrl.replace(/\/$/, "")}/${url.replace(/^\//, "")}`;
				} else {
					return {
						content: [{ type: "text", text: "URL must be absolute or configure baseUrl in .super-curl.json" }],
						details: { error: true },
						isError: true,
					};
				}
			}

			// Build headers and resolve templates
			const rawHeaders: Record<string, string> = {
				...(config.headers || {}),
				...(endpoint?.headers || {}),
				...extraHeaders,
			};
			const finalHeaders: Record<string, string> = {};
			for (const [key, value] of Object.entries(rawHeaders)) {
				finalHeaders[key] = resolveTemplates(value);
			}

			// Add auth
			const auth = endpoint?.auth || config.auth;
			if (auth && auth.type !== "none") {
				Object.assign(finalHeaders, buildAuthHeader(auth));
			}

			// Add content-type for body
			if (body && !finalHeaders["Content-Type"]) {
				finalHeaders["Content-Type"] = "application/json";
			}

			// Merge body with endpoint defaults and resolve templates
			let finalBody = body;
			if (endpoint?.defaultBody && body) {
				try {
					const parsedBody = JSON.parse(body);
					const merged = { ...endpoint.defaultBody, ...parsedBody };
					// Resolve templates in the merged body
					const resolved = resolveTemplatesInObject(merged);
					finalBody = JSON.stringify(resolved);
				} catch {
					// Use as-is but still resolve templates
					finalBody = resolveTemplates(body);
				}
			} else if (endpoint?.defaultBody && !body) {
				const resolved = resolveTemplatesInObject(endpoint.defaultBody);
				finalBody = JSON.stringify(resolved);
			} else if (body) {
				// Resolve templates in the body
				try {
					const parsed = JSON.parse(body);
					const resolved = resolveTemplatesInObject(parsed);
					finalBody = JSON.stringify(resolved);
				} catch {
					finalBody = resolveTemplates(body);
				}
			}

			// Resolve templates in URL
			url = resolveTemplates(url);

			const effectiveMethod = endpoint?.method || method;

			onUpdate?.({
				content: [{ type: "text", text: `${effectiveMethod} ${url}...` }],
			});

			try {
				const controller = new AbortController();
				const timeoutId = setTimeout(() => controller.abort(), config.timeout || 30000);
				signal?.addEventListener("abort", () => controller.abort());

				const response = await fetch(url, {
					method: effectiveMethod,
					headers: finalHeaders,
					body: finalBody,
					signal: controller.signal,
				});

				clearTimeout(timeoutId);

				const contentType = response.headers.get("content-type");
				const duration = Date.now() - startTime;
				const shouldStream = endpoint?.stream || contentType?.includes("text/event-stream");

				let responseText = await response.text();
				let sseResult: SSEParseResult | null = null;

				// Parse SSE if streaming endpoint
				if (shouldStream) {
					sseResult = parseSSEResponse(responseText);
				}

				// Format JSON (for non-streaming responses)
				if (!shouldStream && contentType?.includes("application/json")) {
					try {
						responseText = JSON.stringify(JSON.parse(responseText), null, 2);
					} catch {
						// Keep as-is
					}
				}

				// Save if requested
				let outputFile: string | undefined;
				if (save) {
					outputFile = saveOutput(ctx.cwd, responseText, contentType, url);
				}

				// Build result text
				const statusEmoji = response.ok ? "✓" : "✗";
				let resultText = `${statusEmoji} ${response.status} ${response.statusText} (${duration}ms)\n`;

				// For streaming responses, show parsed summary
				if (sseResult) {
					if (sseResult.outputs.length > 0) {
						resultText += `\n[OK] Generated ${sseResult.outputs.length} output(s):\n`;
						for (const out of sseResult.outputs) {
							const gcsUrl = `gs://${out.bucket_name}/${out.object_key}`;
							resultText += `  • ${out.file_type} (${out.width}x${out.height})\n`;
							resultText += `    ID: ${out.inference_request_id}\n`;
							resultText += `    GCS: ${gcsUrl}\n`;
						}
					}

					if (sseResult.responseText) {
						resultText += `\n[>] Agent response:\n${sseResult.responseText}\n`;
					}

					if (sseResult.errors.length > 0) {
						resultText += `\n[ERR] Errors:\n`;
						for (const err of sseResult.errors) {
							resultText += `  • ${err}\n`;
						}
					}

					// Log generation to output directory
					if (config.outputDir) {
						try {
							const bodyObj = finalBody ? JSON.parse(finalBody) : {};
							const logPaths = logGeneration({
								cwd: ctx.cwd,
								prompt: bodyObj?.generation_params?.positive_prompt || "",
								restructuredPrompt: sseResult.restructuredPrompt,
								chatId: bodyObj?.chat_id,
								generationMode: bodyObj?.generation_params?.generation_mode,
								outputs: sseResult.outputs,
								responseText: sseResult.responseText,
								errors: sseResult.errors,
								endpoint,
							});
							if (logPaths.length > 0) {
								resultText += `\n[DIR] Logged to:\n`;
								for (const p of logPaths) {
									resultText += `  • ${p}\n`;
								}
							}
						} catch {
							// Ignore logging errors
						}
					}

					// Add debug info if no outputs and endpoint has debug config
					if (sseResult.outputs.length === 0 && endpoint?.debug) {
						resultText += buildDebugInfo(ctx.cwd, endpoint, sseResult);
					}
				} else {
					// Regular response - show truncated content
					const maxLength = 10000;
					let displayText = responseText;
					let truncated = false;
					if (responseText.length > maxLength) {
						displayText = responseText.slice(0, maxLength);
						truncated = true;
					}

					resultText += "\n" + displayText;
					if (truncated) {
						resultText += `\n\n[Truncated: ${responseText.length} bytes total]`;
						if (outputFile) resultText += `\n[Full response: ${outputFile}]`;
					} else if (outputFile) {
						resultText += `\n\n[Saved: ${outputFile}]`;
					}
				}

				// Add debug info on HTTP errors
				if (!response.ok && endpoint?.debug) {
					resultText += buildDebugInfo(ctx.cwd, endpoint, sseResult);
				}

				return {
					content: [{ type: "text", text: resultText }],
					details: {
						status: response.status,
						statusText: response.statusText,
						duration,
						contentType,
						truncated: responseText.length > 10000,
						outputFile,
						outputs: sseResult?.outputs,
						errors: sseResult?.errors,
					},
				};
			} catch (error) {
				const duration = Date.now() - startTime;
				const message = error instanceof Error ? error.message : String(error);
				return {
					content: [{ type: "text", text: `Request failed: ${message}` }],
					details: { error: message, duration },
					isError: true,
				};
			}
		},

		renderCall(args, theme) {
			const method = args.method || "GET";
			const url = args.url || "";
			let text = theme.fg("toolTitle", theme.bold("send_request "));
			text += theme.fg("accent", method);
			text += " " + theme.fg("muted", url);
			return new Text(text, 0, 0);
		},

		renderResult(result, { expanded }, theme) {
			const details = result.details || {};

			if (details.error) {
				return new Text(theme.fg("error", `✗ ${result.content?.[0]?.text || "Failed"}`), 0, 0);
			}

			const statusColor = details.status < 300 ? "success" : details.status < 400 ? "warning" : "error";
			let text = theme.fg(statusColor, `${details.status < 300 ? "✓" : "✗"} ${details.status}`);
			text += theme.fg("muted", ` (${details.duration}ms)`);

			if (details.outputFile) {
				text += theme.fg("dim", ` → ${details.outputFile}`);
			}

			if (expanded) {
				const content = result.content?.[0]?.text || "";
				const lines = content.split("\n").slice(2, 20);
				for (const line of lines) {
					text += "\n" + theme.fg("dim", line.slice(0, 100));
				}
				if (content.split("\n").length > 20) {
					text += "\n" + theme.fg("muted", "...");
				}
			}

			return new Text(text, 0, 0);
		},
	});

	// Quick /curl command
	pi.registerCommand("curl", {
		description: "Quick HTTP request: /curl [METHOD] URL [--body JSON]",
		handler: async (args, ctx) => {
			if (!args) {
				ctx.ui.notify("Usage: /curl [METHOD] @endpoint [--body '{...}']", "info");
				return;
			}

			// Parse args: [METHOD] URL [--body JSON]
			const bodyMatch = args.match(/--body\s+['"]?(\{.*\})['"]?/);
			const argsWithoutBody = args.replace(/--body\s+['"]?\{.*\}['"]?/, "").trim();
			const parts = argsWithoutBody.split(/\s+/);
			
			let method: string | null = null;
			let url = parts[0];

			if (parts.length > 1 && ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(parts[0].toUpperCase())) {
				method = parts[0].toUpperCase();
				url = parts[1];
			}

			// If no method specified and it's a named endpoint, use endpoint's method
			if (!method && url.startsWith("@")) {
				config = loadConfig(ctx.cwd);
				const endpointName = url.slice(1);
				const endpoint = config.endpoints?.find((e) => e.name === endpointName);
				if (endpoint?.method) {
					method = endpoint.method;
				}
			}

			// Default to GET if still no method
			method = method || "GET";

			let message = `Use send_request to ${method} ${url}`;
			if (bodyMatch) {
				message += ` with body ${bodyMatch[1]}`;
			}

			pi.sendUserMessage(message);
		},
	});

	// List endpoints command
	pi.registerCommand("endpoints", {
		description: "List configured endpoints",
		handler: async (_args, ctx) => {
			config = loadConfig(ctx.cwd);

			if (!config.endpoints || config.endpoints.length === 0) {
				ctx.ui.notify("No endpoints configured. Add them to .super-curl.json", "info");
				return;
			}

			const lines = config.endpoints.map((e) => `@${e.name}: ${e.method || "GET"} ${e.url}`);
			ctx.ui.notify(`Endpoints:\n${lines.join("\n")}`, "info");
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
