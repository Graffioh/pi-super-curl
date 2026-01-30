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
 *   /curl [METHOD] URL - Quick request (direct)
 *   /curl-agent [METHOD] URL - Quick request via api-tester subagent
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

				const defaultPromptField: TemplateFieldConfig = {
					name: "prompt",
					label: "",
					path: "generation_params.positive_prompt",
				};
				
				function getTemplateFields(): string[] {
					const fields = ["endpoint"];
					const tpl = templateOptions[endpointIndex];
					if (tpl?.fields && tpl.fields.length > 0) {
						for (const f of tpl.fields) fields.push(f.name);
					} else {
						fields.push("prompt");
					}
					fields.push("body");
					return fields;
				}
				
				function getTemplateFieldConfigs(): TemplateFieldConfig[] {
					const tpl = templateOptions[endpointIndex];
					if (tpl?.fields && tpl.fields.length > 0) return tpl.fields;
					return [defaultPromptField];
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
							for (const fieldConfig of fieldConfigs) {
								if (!fieldConfig.path) continue;
								const editor = fieldEditors.get(fieldConfig.name);
								const value = editor?.getText().trim() || "";
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
					if (matchesKey(data, Key.escape)) {
						done({ method: METHODS[methodIndex], url: "", body: "", headers: "", cancelled: true });
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

					// Title with tabs
					const templateTab = mode === "template" 
						? theme.bg("selectedBg", theme.fg("text", " Template "))
						: theme.fg("dim", " Template ");
					const defaultTab = mode === "default"
						? theme.bg("selectedBg", theme.fg("text", " Default "))
						: theme.fg("dim", " Default ");
					const title = " Super Curl ";
					
					function topBorder() {
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

			// Delegate to api-tester subagent
			pi.sendUserMessage(`Use subagent api-tester to test: ${task}`);
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
