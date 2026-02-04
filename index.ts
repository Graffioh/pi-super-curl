/**
 * Super Curl - HTTP Request Extension for Pi
 *
 * Two modes:
 * 1. Default Mode: Simple Postman-like client - manually fill URL, method, headers, body
 * 2. Template Mode: Pre-configured requests with custom input fields
 *
 * Commands:
 *   /scurl - Open request builder (Ctrl+T to switch modes, Ctrl+U to import cURL)
 *   /scurl-history - Browse and replay past requests
 *   /scurl-log - Capture logs after request (requires customLogging config)
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Text, Editor, type EditorTheme, Key, matchesKey } from "@mariozechner/pi-tui";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import jwt from "jsonwebtoken";
import { v4 as uuidv4, v7 as uuidv7 } from "uuid";
import dotenv from "dotenv";

// ===== Configuration Types =====

interface AuthConfig {
	type: "bearer" | "api-key" | "basic" | "none" | "jwt";
	token?: string;        // For bearer/api-key
	header?: string;       // Custom header name for api-key
	username?: string;     // For basic auth
	password?: string;     // For basic auth
	secret?: string;       // For JWT
	algorithm?: jwt.Algorithm;
	expiresIn?: number;    // JWT expiry in seconds
	payload?: Record<string, unknown>;  // JWT payload
}

// Template field: user input that gets injected into the request
interface TemplateFieldConfig {
	name: string;
	label: string;
	hint?: string;
	type?: "text" | "multiline" | "json";
	path?: string;           // JSON path to inject value (e.g., "data.message")
	required?: boolean;
	default?: string;
	sendToAgent?: boolean;   // If true, value goes to pi agent, not HTTP body
}

// Template: self-contained pre-configured request
interface TemplateConfig {
	name: string;
	description?: string;
	
	// Request config (self-contained)
	baseUrl?: string;        // Can use $ENV_VAR
	url: string;             // Endpoint path or full URL
	method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
	stream?: boolean;
	
	// Auth & headers specific to this template
	auth?: AuthConfig;
	headers?: Record<string, string>;
	
	// Body template
	body?: Record<string, unknown>;
	
	// User input fields
	fields?: TemplateFieldConfig[];
	appendField?: boolean;   // Auto-add "Additional Instructions" field
}

// Default settings for simple Postman mode
interface DefaultsConfig {
	baseUrl?: string;
	timeout?: number;
	envFile?: string;
	auth?: AuthConfig;
	headers?: Record<string, string>;
}

// Custom logging for debugging
interface CustomLoggingConfig {
	enabled: boolean;
	outputDir: string;
	logs?: Record<string, string>;  // { "name": "path/to/log" }
	postScript?: string;
}

// Root config structure
interface SuperCurlConfig {
	defaults?: DefaultsConfig;
	templates?: TemplateConfig[];
	customLogging?: CustomLoggingConfig;
	
	// Legacy support (deprecated, will be removed)
	baseUrl?: string;
	timeout?: number;
	envFile?: string;
	auth?: AuthConfig;
	headers?: Record<string, string>;
	endpoints?: any[];
}

// ===== History Types =====

interface HistoryEntry {
	id: string;
	timestamp: number;
	method: string;
	url: string;
	body?: string;
	headers?: Record<string, string>;
	template?: string;
}

// ===== Request Builder Types =====

interface RequestBuilderResult {
	method: string;
	url: string;
	body: string;
	headers: string;
	cancelled: boolean;
	template?: string;
	agentInstructions?: string;
}

// ===== SSE Parsing Types =====

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
	responseText: string;
	outputs: SSEOutput[];
	errors: string[];
	toolCalls: Array<{ name: string; input: unknown }>;
	restructuredPrompt?: string;
}

// ===== Constants =====

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
const HISTORY_PATH = path.join(os.homedir(), ".super-curl-history.json");
const MAX_HISTORY = 50;

// ===== Extension =====

export default function superCurlExtension(pi: ExtensionAPI) {
	let config: SuperCurlConfig = {};
	let configDir: string = "";
	let loadedEnv: Record<string, string> = {};

	// ===== Setup =====

	function setupSymlinks() {
		const piSkillsDir = path.join(os.homedir(), ".pi", "agent", "skills");
		const piAgentsDir = path.join(os.homedir(), ".pi", "agent", "agents");
		const extensionDir = path.dirname(new URL(import.meta.url).pathname);

		if (!fs.existsSync(piSkillsDir)) {
			fs.mkdirSync(piSkillsDir, { recursive: true });
		}
		if (!fs.existsSync(piAgentsDir)) {
			fs.mkdirSync(piAgentsDir, { recursive: true });
		}

		const skillSource = path.join(extensionDir, "skills", "send-request");
		const skillTarget = path.join(piSkillsDir, "send-request");
		if (fs.existsSync(skillSource) && !fs.existsSync(skillTarget)) {
			try { fs.symlinkSync(skillSource, skillTarget, "dir"); } catch {}
		}

		const agentSource = path.join(extensionDir, "agents", "api-tester.md");
		const agentTarget = path.join(piAgentsDir, "api-tester.md");
		if (fs.existsSync(agentSource) && !fs.existsSync(agentTarget)) {
			try { fs.symlinkSync(agentSource, agentTarget, "file"); } catch {}
		}
	}

	setupSymlinks();

	// ===== Config Loading =====

	function loadConfig(cwd: string): SuperCurlConfig {
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

					// Load env file
					const envFile = cfg.defaults?.envFile || cfg.envFile;
					if (envFile) loadEnvFile(cwd, envFile);

					return cfg;
				} catch {}
			}
		}
		configDir = cwd;
		return {};
	}

	function loadEnvFile(cwd: string, envFile: string) {
		let envPath = envFile;
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

	// Get effective defaults (with legacy fallback)
	function getDefaults(): DefaultsConfig {
		if (config.defaults) return config.defaults;
		// Legacy fallback
		return {
			baseUrl: config.baseUrl,
			timeout: config.timeout,
			envFile: config.envFile,
			auth: config.auth,
			headers: config.headers,
		};
	}

	// ===== Value Resolution =====

	function resolveValue(value: string | undefined): string | undefined {
		if (!value) return undefined;
		if (value.startsWith("$")) {
			const varName = value.slice(1);
			return loadedEnv[varName] || process.env[varName];
		}
		return value;
	}

	function resolveTemplates(text: string): string {
		return text.replace(/\{\{([^}]+)\}\}/g, (match, expr) => {
			const trimmed = expr.trim();
			if (trimmed === "uuid" || trimmed === "uuidv4") return uuidv4();
			if (trimmed === "uuidv7") return uuidv7();
			if (trimmed === "timestamp") return Math.floor(Date.now() / 1000).toString();
			if (trimmed === "timestamp_ms") return Date.now().toString();
			if (trimmed === "date") return new Date().toISOString();
			if (trimmed.startsWith("env.")) {
				const varName = trimmed.slice(4);
				return loadedEnv[varName] || process.env[varName] || "";
			}
			if (trimmed.startsWith("$")) {
				const varName = trimmed.slice(1);
				return loadedEnv[varName] || process.env[varName] || "";
			}
			return match;
		});
	}

	function resolveTemplatesInObject(obj: unknown): unknown {
		if (typeof obj === "string") return resolveTemplates(obj);
		if (Array.isArray(obj)) return obj.map(resolveTemplatesInObject);
		if (obj && typeof obj === "object") {
			const result: Record<string, unknown> = {};
			for (const [key, value] of Object.entries(obj)) {
				result[key] = resolveTemplatesInObject(value);
			}
			return result;
		}
		return obj;
	}

	// ===== History =====

	function loadHistory(): HistoryEntry[] {
		try {
			if (fs.existsSync(HISTORY_PATH)) {
				return JSON.parse(fs.readFileSync(HISTORY_PATH, "utf-8")) as HistoryEntry[];
			}
		} catch {}
		return [];
	}

	function saveHistory(history: HistoryEntry[]): void {
		try { fs.writeFileSync(HISTORY_PATH, JSON.stringify(history, null, 2)); } catch {}
	}

	function addToHistory(entry: Omit<HistoryEntry, "id" | "timestamp">): void {
		const history = loadHistory();
		history.unshift({ ...entry, id: uuidv4(), timestamp: Date.now() });
		saveHistory(history.slice(0, MAX_HISTORY));
	}

	function deleteFromHistory(id: string): void {
		const history = loadHistory().filter(h => h.id !== id);
		saveHistory(history);
	}

	function clearHistory(): void {
		saveHistory([]);
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
		const result: ParsedCurl = { method: "GET", url: "", headers: {} };

		let cmd = curlCommand.replace(/\\\s*\n/g, " ").replace(/\s+/g, " ").trim();
		if (cmd.toLowerCase().startsWith("curl ")) cmd = cmd.slice(5).trim();

		// Tokenize
		const tokens: string[] = [];
		let current = "";
		let inQuote: string | null = null;
		let escape = false;

		for (const char of cmd) {
			if (escape) { current += char; escape = false; continue; }
			if (char === "\\") { escape = true; continue; }
			if (inQuote) {
				if (char === inQuote) inQuote = null;
				else current += char;
			} else {
				if (char === '"' || char === "'") inQuote = char;
				else if (char === " ") { if (current) { tokens.push(current); current = ""; } }
				else current += char;
			}
		}
		if (current) tokens.push(current);

		// Parse
		let i = 0;
		while (i < tokens.length) {
			const token = tokens[i];

			if (token === "-X" || token === "--request") {
				if (++i < tokens.length) result.method = tokens[i].toUpperCase();
				i++; continue;
			}

			if (token === "-H" || token === "--header") {
				if (++i < tokens.length) {
					const colonIdx = tokens[i].indexOf(":");
					if (colonIdx > 0) {
						result.headers[tokens[i].slice(0, colonIdx).trim()] = tokens[i].slice(colonIdx + 1).trim();
					}
				}
				i++; continue;
			}

			if (token === "-d" || token === "--data" || token === "--data-raw" || token === "--data-binary") {
				if (++i < tokens.length) {
					result.body = tokens[i];
					if (result.method === "GET") result.method = "POST";
				}
				i++; continue;
			}

			if (token === "--json") {
				if (++i < tokens.length) {
					result.body = tokens[i];
					result.headers["Content-Type"] = "application/json";
					if (result.method === "GET") result.method = "POST";
				}
				i++; continue;
			}

			// Skip common flags
			const skipFlags = ["-i", "--include", "-s", "--silent", "-S", "--show-error", "-v", "--verbose",
				"-k", "--insecure", "-L", "--location", "-f", "--fail", "--compressed", "--http1.1", "--http2"];
			const skipWithArg = ["-o", "--output", "-w", "--write-out", "-A", "--user-agent",
				"-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "--connect-timeout", "-m", "--max-time"];

			if (skipFlags.includes(token)) { i++; continue; }
			if (skipWithArg.includes(token)) { i += 2; continue; }

			if (!token.startsWith("-") && !result.url) result.url = token;
			i++;
		}

		if (!result.url) result.error = "No URL found in cURL command";
		return result;
	}

	// ===== Auth =====

	function generateJwtToken(auth: AuthConfig): string {
		const secret = resolveValue(auth.secret);
		if (!secret) throw new Error("JWT secret not found");

		const payload = resolveTemplatesInObject(auth.payload || {}) as jwt.JwtPayload;
		const now = Math.floor(Date.now() / 1000);
		if (!payload.iat) payload.iat = now;
		if (!payload.exp) payload.exp = now + (auth.expiresIn || 3600);

		return jwt.sign(payload, secret, { algorithm: auth.algorithm || "HS256" });
	}

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
				headers["Authorization"] = `Bearer ${generateJwtToken(auth)}`;
				break;
			}
		}
		return headers;
	}

	// ===== SSE Parsing =====

	function parseSSEResponse(rawResponse: string): SSEParseResult {
		const result: SSEParseResult = { responseText: "", outputs: [], errors: [], toolCalls: [] };

		for (const line of rawResponse.split("\n")) {
			if (!line.startsWith("data: ") || line === "data: [DONE]") continue;

			try {
				const data = JSON.parse(line.slice(6));

				if (data.type === "text-delta" && data.delta) {
					result.responseText += data.delta;
				}

				if (data.type === "error" || data.error) {
					result.errors.push(data.error || data.message || JSON.stringify(data));
				}

				if (data.type === "tool-input-available" && data.input) {
					result.toolCalls.push({ name: data.toolName, input: data.input });
					const promptFields = ["image_to_image_prompt", "video_prompt", "text_to_image_prompt", 
						"image_to_video_prompt", "audio_prompt"];
					for (const field of promptFields) {
						if (data.input[field]) { result.restructuredPrompt = data.input[field]; break; }
					}
				}

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
			} catch {}
		}

		return result;
	}

	// ===== Custom Logging =====

	function copyCustomLogs(cwd: string, destDir: string): void {
		const logs = config.customLogging?.logs;
		if (!logs) return;

		for (const [name, logPath] of Object.entries(logs)) {
			const src = path.isAbsolute(logPath) ? logPath : path.resolve(cwd, logPath);
			if (fs.existsSync(src)) {
				try { fs.copyFileSync(src, path.join(destDir, `${name}-logs.txt`)); } catch {}
			}
		}
	}

	// ===== Commands =====

	pi.registerCommand("scurl", {
		description: "Open Super Curl request builder (Ctrl+T for templates)",
		handler: async (_args, ctx) => {
			config = loadConfig(ctx.cwd);
			const defaults = getDefaults();
			const templates = config.templates || [];

			const result = await ctx.ui.custom<RequestBuilderResult>((tui, theme, _kb, done) => {
				let mode: "template" | "default" = templates.length > 0 ? "template" : "default";
				let templateIndex = 0;
				let bodyScrollOffset = 0;
				const bodyMaxVisible = 8;
				let methodIndex = 0;
				let fieldEditors: Map<string, Editor> = new Map();
				let templateFieldIndex = 0;
				type CustomField = "method" | "url" | "body" | "headers";
				let customField: CustomField = "method";
				let cachedLines: string[] | undefined;
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

				// Initialize default headers
				if (defaults.headers) {
					const headerLines = Object.entries(defaults.headers).map(([k, v]) => `${k}: ${v}`).join("\n");
					headersEditor.setText(headerLines);
				}

				const autoInstructionsField: TemplateFieldConfig = {
					name: "instructions",
					label: "Additional Instructions",
					hint: "Sent to pi agent",
					sendToAgent: true,
				};

				function getTemplateFields(): string[] {
					const fields = ["template"];
					const tpl = templates[templateIndex];
					if (tpl?.fields?.length) {
						for (const f of tpl.fields) fields.push(f.name);
					}
					if (tpl?.appendField) fields.push("instructions");
					fields.push("body");
					return fields;
				}

				function getTemplateFieldConfigs(): TemplateFieldConfig[] {
					const tpl = templates[templateIndex];
					let configs: TemplateFieldConfig[] = tpl?.fields ? [...tpl.fields] : [];
					if (tpl?.appendField) configs.push(autoInstructionsField);
					return configs;
				}

				function getCurrentTemplateField(): string {
					return getTemplateFields()[templateFieldIndex] || "template";
				}

				function getFieldEditor(fieldName: string): Editor {
					if (!fieldEditors.has(fieldName)) {
						const editor = new Editor(tui, editorTheme);
						const tpl = templates[templateIndex];
						const fieldConfig = tpl?.fields?.find(f => f.name === fieldName);
						if (fieldConfig?.default) editor.setText(fieldConfig.default);
						fieldEditors.set(fieldName, editor);
					}
					return fieldEditors.get(fieldName)!;
				}

				function loadTemplate(idx: number) {
					if (idx < 0 || idx >= templates.length) return;
					const tpl = templates[idx];
					bodyScrollOffset = 0;

					const methodIdx = METHODS.indexOf(tpl.method || "GET");
					if (methodIdx >= 0) methodIndex = methodIdx;

					if (tpl.body && Object.keys(tpl.body).length > 0) {
						bodyEditor.setText(JSON.stringify(tpl.body, null, 2));
					} else {
						bodyEditor.setText("");
					}

					// Template-specific headers (merged with defaults)
					const allHeaders = { ...defaults.headers, ...tpl.headers };
					if (Object.keys(allHeaders).length > 0) {
						headersEditor.setText(Object.entries(allHeaders).map(([k, v]) => `${k}: ${v}`).join("\n"));
					} else {
						headersEditor.setText("");
					}

					fieldEditors = new Map();
					for (const f of tpl.fields || []) {
						const editor = new Editor(tui, editorTheme);
						if (f.default) editor.setText(f.default);
						fieldEditors.set(f.name, editor);
					}

					templateFieldIndex = 0;
				}

				function applyCurl(parsed: ParsedCurl): void {
					const methodIdx = METHODS.indexOf(parsed.method as typeof METHODS[number]);
					if (methodIdx >= 0) methodIndex = methodIdx;
					urlEditor.setText(parsed.url);
					headersEditor.setText(Object.entries(parsed.headers).map(([k, v]) => `${k}: ${v}`).join("\n"));
					if (parsed.body) {
						try { bodyEditor.setText(JSON.stringify(JSON.parse(parsed.body), null, 2)); }
						catch { bodyEditor.setText(parsed.body); }
					} else {
						bodyEditor.setText("");
					}
					mode = "default";
					customField = "url";
				}

				function refresh() {
					cachedLines = undefined;
					tui.requestRender();
				}

				function getActiveEditor(): Editor | null {
					if (mode === "template") {
						const currentField = getCurrentTemplateField();
						if (currentField === "template") return null;
						if (currentField === "body") return bodyEditor;
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

				function setAtPath(obj: Record<string, unknown>, pathStr: string, value: unknown): void {
					const segments: (string | number)[] = [];
					const regex = /([^.\[\]]+)|\[(\d+)\]/g;
					let match;
					while ((match = regex.exec(pathStr)) !== null) {
						if (match[1] !== undefined) segments.push(match[1]);
						else if (match[2] !== undefined) segments.push(parseInt(match[2], 10));
					}

					let current: unknown = obj;
					for (let i = 0; i < segments.length - 1; i++) {
						const seg = segments[i];
						const nextSeg = segments[i + 1];
						const currentObj = current as Record<string, unknown>;
						if (!(seg in currentObj) || typeof currentObj[seg as string] !== "object") {
							currentObj[seg as string] = typeof nextSeg === "number" ? [] : {};
						}
						current = currentObj[seg as string];
					}
					(current as Record<string, unknown>)[segments[segments.length - 1] as string] = value;
				}

				function buildFinalBody(): { body: string; agentInstructions?: string } {
					const bodyText = bodyEditor.getText().trim();
					if (mode === "template") {
						const fieldConfigs = getTemplateFieldConfigs();
						try {
							const body = bodyText ? JSON.parse(bodyText) : {};
							const agentInstructionParts: string[] = [];

							for (const fieldConfig of fieldConfigs) {
								const editor = fieldEditors.get(fieldConfig.name);
								const value = editor?.getText().trim() || "";
								
								if (fieldConfig.sendToAgent && value) {
									agentInstructionParts.push(value);
								} else if (fieldConfig.path && value) {
									setAtPath(body, fieldConfig.path, value);
								}
							}

							return {
								body: JSON.stringify(body),
								agentInstructions: agentInstructionParts.length > 0 ? agentInstructionParts.join("\n") : undefined,
							};
						} catch {
							return { body: bodyText };
						}
					}
					return { body: bodyText };
				}

				function getUrl(): string {
					if (mode === "template" && templates.length > 0) {
						const tpl = templates[templateIndex];
						const baseUrl = resolveValue(tpl.baseUrl) || resolveValue(defaults.baseUrl) || "";
						return baseUrl + tpl.url;
					}
					const url = urlEditor.getText().trim();
					const baseUrl = resolveValue(defaults.baseUrl) || "";
					if (url.startsWith("http://") || url.startsWith("https://")) return url;
					return baseUrl + url;
				}

				function submit() {
					const { body, agentInstructions } = buildFinalBody();
					const tpl = mode === "template" ? templates[templateIndex] : undefined;
					
					done({
						method: tpl?.method || METHODS[methodIndex],
						url: getUrl(),
						body,
						headers: headersEditor.getText().trim(),
						cancelled: false,
						template: tpl?.name,
						agentInstructions,
					});
				}

				function handleInput(data: string) {
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
							if (!curlText) { curlImportError = "Please paste a cURL command"; refresh(); return; }
							const parsed = parseCurl(curlText);
							if (parsed.error) { curlImportError = parsed.error; refresh(); return; }
							applyCurl(parsed);
							showCurlImport = false;
							curlImportError = null;
							curlEditor.setText("");
							refresh();
							return;
						}

						curlEditor.handleInput(data);
						curlImportError = null;
						refresh();
						return;
					}

					if (matchesKey(data, Key.escape)) {
						done({ method: METHODS[methodIndex], url: "", body: "", headers: "", cancelled: true });
						return;
					}

					if (matchesKey(data, Key.ctrl("u"))) {
						showCurlImport = true;
						curlImportError = null;
						curlEditor.setText("");
						refresh();
						return;
					}

					if (matchesKey(data, Key.ctrl("t"))) {
						if (mode === "template") {
							mode = "default";
							customField = "method";
							methodIndex = 0;
							urlEditor.setText("");
							bodyEditor.setText("");
							if (defaults.headers) {
								headersEditor.setText(Object.entries(defaults.headers).map(([k, v]) => `${k}: ${v}`).join("\n"));
							} else {
								headersEditor.setText("");
							}
						} else if (templates.length > 0) {
							mode = "template";
							templateFieldIndex = 0;
							loadTemplate(templateIndex);
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
							const fields: CustomField[] = (method === "GET") ? ["method", "url", "headers"] : ["method", "url", "body", "headers"];
							customField = fields[(fields.indexOf(customField) + 1) % fields.length];
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
							const fields: CustomField[] = (method === "GET") ? ["method", "url", "headers"] : ["method", "url", "body", "headers"];
							customField = fields[(fields.indexOf(customField) - 1 + fields.length) % fields.length];
						}
						refresh();
						return;
					}

					// Template selector
					if (mode === "template" && getCurrentTemplateField() === "template") {
						if (matchesKey(data, Key.up) || matchesKey(data, Key.left)) {
							templateIndex = (templateIndex - 1 + templates.length) % templates.length;
							loadTemplate(templateIndex);
							refresh();
							return;
						}
						if (matchesKey(data, Key.down) || matchesKey(data, Key.right)) {
							templateIndex = (templateIndex + 1) % templates.length;
							loadTemplate(templateIndex);
							refresh();
							return;
						}
					}

					// Method selector
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

					// Body scrolling
					if (mode === "template" && getCurrentTemplateField() === "body") {
						const bodyLines = bodyEditor.getText().split("\n");
						const maxScroll = Math.max(0, bodyLines.length - bodyMaxVisible);
						if (matchesKey(data, Key.up)) { bodyScrollOffset = Math.max(0, bodyScrollOffset - 1); refresh(); return; }
						if (matchesKey(data, Key.down)) { bodyScrollOffset = Math.min(maxScroll, bodyScrollOffset + 1); refresh(); return; }
						bodyEditor.handleInput(data);
						const newMaxScroll = Math.max(0, bodyEditor.getText().split("\n").length - bodyMaxVisible);
						if (bodyScrollOffset > newMaxScroll) bodyScrollOffset = newMaxScroll;
						refresh();
						return;
					}

					const editor = getActiveEditor();
					if (editor) { editor.handleInput(data); refresh(); }
				}

				function render(width: number): string[] {
					if (cachedLines) return cachedLines;

					const lines: string[] = [];
					const boxWidth = Math.min(80, width - 4);
					const innerWidth = boxWidth - 4;
					const method = METHODS[methodIndex];

					function makeTopBorder(title: string) {
						const titleLen = title.replace(/[^\x20-\x7E]/g, " ").length;
						return theme.fg("accent", "╭") + theme.fg("accent", theme.bold(title)) + theme.fg("accent", "─".repeat(boxWidth - 2 - titleLen) + "╮");
					}
					function makeBottomBorder() { return theme.fg("accent", "╰" + "─".repeat(boxWidth - 2) + "╯"); }
					function makeDivider() { return theme.fg("accent", "├" + "─".repeat(boxWidth - 2) + "┤"); }
					function makeRow(content: string) {
						const contentLen = content.replace(/\x1b\[[0-9;]*m/g, "").length;
						return theme.fg("accent", "│ ") + content + " ".repeat(Math.max(0, innerWidth - contentLen)) + theme.fg("accent", " │");
					}
					function fieldLabel(label: string, active: boolean, hint?: string) {
						const labelText = active ? theme.fg("warning", theme.bold(label)) : theme.fg("muted", label);
						return hint ? labelText + " " + theme.fg("dim", `(${hint})`) : labelText;
					}

					// cURL Import Popup
					if (showCurlImport) {
						lines.push("");
						lines.push(makeTopBorder(" Import cURL "));
						lines.push(makeRow(""));
						lines.push(makeRow(theme.fg("muted", "Paste your cURL command below:")));
						lines.push(makeRow(""));
						const curlLines = curlEditor.render(innerWidth - 2);
						for (let i = 0; i < Math.min(curlLines.length, 10); i++) lines.push(makeRow("  " + curlLines[i]));
						if (curlLines.length > 10) lines.push(makeRow(theme.fg("dim", `  ... ${curlLines.length - 10} more lines`)));
						if (curlImportError) { lines.push(makeRow("")); lines.push(makeRow(theme.fg("error", "  ✗ " + curlImportError))); }
						lines.push(makeDivider());
						lines.push(makeRow(theme.fg("muted", "Ctrl+Enter") + theme.fg("dim", " import  ") + theme.fg("muted", "Esc") + theme.fg("dim", " cancel")));
						lines.push(makeBottomBorder());
						lines.push("");
						cachedLines = lines;
						return lines;
					}

					// Main UI
					const templateTab = mode === "template" ? theme.bg("selectedBg", theme.fg("text", " Template ")) : theme.fg("dim", " Template ");
					const defaultTab = mode === "default" ? theme.bg("selectedBg", theme.fg("text", " Default ")) : theme.fg("dim", " Default ");

					lines.push("");
					lines.push(makeTopBorder(" Super Curl "));
					const tabsContent = defaultTab + "  " + templateTab;
					const tabsLen = tabsContent.replace(/\x1b\[[0-9;]*m/g, "").length;
					lines.push(makeRow(tabsContent + " ".repeat(Math.max(1, innerWidth - tabsLen - 8)) + theme.fg("dim", "(Ctrl+T)")));
					lines.push(makeDivider());

					if (mode === "template") {
						const templateActive = getCurrentTemplateField() === "template";
						lines.push(makeRow(fieldLabel("Template:", templateActive, "↑↓ to change")));

						const maxVisible = 3;
						const startIdx = Math.max(0, templateIndex - 1);
						const endIdx = Math.min(templates.length, startIdx + maxVisible);

						for (let i = startIdx; i < endIdx; i++) {
							const tpl = templates[i];
							const isSelected = i === templateIndex;
							const prefix = isSelected ? (templateActive ? "▸ " : "› ") : "  ";
							const label = tpl.description || `${tpl.name} (${tpl.method || "GET"} ${tpl.url})`;
							const text = isSelected && templateActive ? theme.fg("warning", prefix + label)
								: isSelected ? theme.fg("text", prefix + label)
								: theme.fg("dim", prefix + label);
							lines.push(makeRow(text));
						}
						if (templates.length > maxVisible) lines.push(makeRow(theme.fg("dim", `  (${templateIndex + 1}/${templates.length})`)));
						lines.push(makeDivider());

						// Fields
						const fieldConfigs = getTemplateFieldConfigs();
						const currentField = getCurrentTemplateField();

						for (const fieldConfig of fieldConfigs) {
							const fieldActive = currentField === fieldConfig.name;
							const labelText = fieldConfig.label || fieldConfig.name;
							const hint = fieldConfig.hint || (fieldConfig.path ? `→ ${fieldConfig.path}` : undefined);
							lines.push(makeRow(fieldLabel(labelText ? `${labelText}:` : "", fieldActive, hint)));
							const editor = getFieldEditor(fieldConfig.name);
							const editorLines = editor.render(innerWidth - 2);
							const maxLines = fieldActive ? 5 : 2;
							for (const line of editorLines.slice(0, maxLines)) {
								lines.push(makeRow((fieldActive ? "  " : theme.fg("muted", "  ")) + line));
							}
							const textLineCount = editor.getText().trim().split("\n").length;
							if (textLineCount > maxLines) lines.push(makeRow(theme.fg("dim", `    ... ${textLineCount - maxLines} more`)));
							lines.push(makeRow("  " + theme.fg("dim", "─".repeat(innerWidth - 4))));
							lines.push(makeDivider());
						}

						// Body
						const bodyActive = currentField === "body";
						const bodyText = bodyEditor.getText();
						if (bodyActive) {
							const bodyLines = bodyEditor.render(innerWidth - 2);
							const scrollable = bodyLines.length > bodyMaxVisible;
							const scrollHint = scrollable ? ` ↑↓ scroll ${bodyScrollOffset + 1}-${Math.min(bodyScrollOffset + bodyMaxVisible, bodyLines.length)}/${bodyLines.length}` : "";
							lines.push(makeRow(fieldLabel("Body:", true, "optional, JSON") + theme.fg("dim", scrollHint)));
							for (const line of bodyLines.slice(bodyScrollOffset, bodyScrollOffset + bodyMaxVisible)) {
								lines.push(makeRow("  " + line));
							}
						} else {
							const bodyHint = bodyText.trim() ? theme.fg("dim", " (has content)") : "";
							lines.push(makeRow(theme.fg("muted", "  Body") + theme.fg("dim", " optional") + bodyHint));
						}

					} else {
						// DEFAULT MODE
						const methodActive = customField === "method";
						const methodButtons = METHODS.map((m, i) => {
							const isSelected = i === methodIndex;
							if (isSelected && methodActive) return theme.bg("selectedBg", theme.fg("text", ` ${m} `));
							if (isSelected) return theme.fg("accent", `[${m}]`);
							return theme.fg("dim", ` ${m} `);
						}).join(" ");
						lines.push(makeRow(fieldLabel("Method:", methodActive) + "  " + methodButtons + (methodActive ? theme.fg("dim", "  ←→ change") : "")));
						lines.push(makeDivider());

						const urlActive = customField === "url";
						lines.push(makeRow(fieldLabel("URL:", urlActive, "endpoint path or full URL")));
						for (const line of urlEditor.render(innerWidth - 2)) {
							lines.push(makeRow((urlActive ? "  " : theme.fg("muted", "  ")) + line));
						}

						if (method !== "GET") {
							lines.push(makeDivider());
							const bodyActive = customField === "body";
							lines.push(makeRow(fieldLabel("Body:", bodyActive, "JSON")));
							const bodyLines = bodyEditor.render(innerWidth - 2);
							const maxLines = bodyActive ? 10 : 3;
							for (const line of bodyLines.slice(0, maxLines)) {
								lines.push(makeRow((bodyActive ? "  " : theme.fg("muted", "  ")) + line));
							}
							if (bodyLines.length > maxLines) lines.push(makeRow(theme.fg("dim", `    ... ${bodyLines.length - maxLines} more`)));
						}

						lines.push(makeDivider());
						const headersActive = customField === "headers";
						lines.push(makeRow(fieldLabel("Headers:", headersActive, "Name: Value")));
						const headerLines = headersEditor.render(innerWidth - 2);
						const maxHeaderLines = headersActive ? 5 : 3;
						for (const line of headerLines.slice(0, maxHeaderLines)) {
							lines.push(makeRow((headersActive ? "  " : theme.fg("muted", "  ")) + line));
						}
					}

					lines.push(makeBottomBorder());
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

				// Initialize template mode
				if (templates.length > 0) loadTemplate(0);

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

			// Build auth headers if template has auth config
			const tpl = result.template ? templates.find(t => t.name === result.template) : undefined;
			const auth = tpl?.auth || getDefaults().auth;
			if (auth && auth.type !== "none") {
				const authHeaders = buildAuthHeader(auth);
				Object.assign(extraHeaders, authHeaders);
			}

			// Build task
			let task = `${result.method} ${result.url}`;
			if (result.body) task += ` with body ${result.body}`;
			const headerEntries = Object.entries(extraHeaders);
			if (headerEntries.length > 0) {
				task += ` with headers: ${headerEntries.map(([k, v]) => `${k}: ${v}`).join(", ")}`;
			}

			// Stream option
			if (tpl?.stream) task += " (stream: true)";

			// Save to history
			addToHistory({
				method: result.method,
				url: result.url,
				body: result.body || undefined,
				headers: Object.keys(extraHeaders).length > 0 ? extraHeaders : undefined,
				template: result.template,
			});

			// Delegate to api-tester
			let message = `Use subagent api-tester to test: ${task}`;
			if (result.agentInstructions) {
				message += `\n\nAdditional instructions for you (pi): ${result.agentInstructions}`;
			}

			pi.sendUserMessage(message);
		},
	});

	// /scurl-log command
	pi.registerCommand("scurl-log", {
		description: "Capture logs from last request (uses customLogging config)",
		handler: async (_args, ctx) => {
			config = loadConfig(ctx.cwd);

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

			const baseOutputDir = config.customLogging.outputDir.startsWith("~")
				? path.join(os.homedir(), config.customLogging.outputDir.slice(1))
				: path.resolve(ctx.cwd, config.customLogging.outputDir);

			const outputDir = path.join(baseOutputDir, String(Date.now()));
			if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

			const copiedLogs: string[] = [];
			const missingLogs: string[] = [];

			for (const [name, logPath] of Object.entries(config.customLogging.logs)) {
				const src = path.isAbsolute(logPath) ? logPath : path.resolve(ctx.cwd, logPath);
				const dest = path.join(outputDir, `${name}.txt`);
				if (fs.existsSync(src)) {
					try { fs.copyFileSync(src, dest); copiedLogs.push(`${name}.txt`); }
					catch { missingLogs.push(`${name} (copy failed)`); }
				} else {
					missingLogs.push(`${name} (not found)`);
				}
			}

			let postScriptResult = "";
			if (config.customLogging.postScript) {
				const scriptPath = path.isAbsolute(config.customLogging.postScript)
					? config.customLogging.postScript
					: path.resolve(configDir, config.customLogging.postScript);

				if (fs.existsSync(scriptPath)) {
					ctx.ui.notify("Processing...", "info");
					try {
						const { execSync } = require("child_process");
						execSync(`"${scriptPath}" "${outputDir}"`, { cwd: ctx.cwd, stdio: "pipe", timeout: 120000 });
						postScriptResult = "\n  Post-script: ✓ executed";
					} catch (err: any) {
						if (err?.status === 2) {
							ctx.ui.notify("⚠️ Log already processed\n  Run a new /scurl request first.", "warning");
							return;
						}
						postScriptResult = `\n  Post-script: ✗ ${err instanceof Error ? err.message : "failed"}`;
					}
				} else {
					postScriptResult = `\n  Post-script: ✗ not found at ${scriptPath}`;
				}
			}

			if (copiedLogs.length > 0) {
				ctx.ui.notify(
					`✓ Logs saved to ${outputDir}\n  Files: ${copiedLogs.join(", ")}` +
					(missingLogs.length > 0 ? `\n  Missing: ${missingLogs.join(", ")}` : "") +
					postScriptResult,
					"success"
				);
			} else {
				ctx.ui.notify(`✗ No logs found\n  Missing: ${missingLogs.join(", ")}`, "error");
			}
		},
	});

	// /scurl-history command
	pi.registerCommand("scurl-history", {
		description: "Browse and replay request history",
		handler: async (_args, ctx) => {
			const history = loadHistory();

			if (history.length === 0) {
				ctx.ui.notify("No request history yet. Use /scurl to make requests.", "info");
				return;
			}

			interface HistoryBrowserResult {
				action: "replay" | "delete" | "clear" | "cancel";
				entry?: HistoryEntry;
			}

			const result = await ctx.ui.custom<HistoryBrowserResult>((tui, theme, _kb, done) => {
				let selectedIndex = 0;
				let scrollOffset = 0;
				const maxVisible = 12;
				let showDetails = false;
				let confirmClear = false;
				let cachedLines: string[] | undefined;

				function refresh() { cachedLines = undefined; tui.requestRender(); }

				function handleInput(data: string) {
					if (confirmClear) {
						if (data.toLowerCase() === "y") { clearHistory(); done({ action: "clear" }); return; }
						confirmClear = false; refresh(); return;
					}

					if (matchesKey(data, Key.escape)) {
						if (showDetails) { showDetails = false; refresh(); return; }
						done({ action: "cancel" }); return;
					}

					if (matchesKey(data, Key.enter)) {
						const entry = history[selectedIndex];
						if (entry) done({ action: "replay", entry });
						return;
					}

					if (data === "d" || data === "D") { showDetails = !showDetails; refresh(); return; }

					if (data === "x" || data === "X" || matchesKey(data, Key.delete) || matchesKey(data, Key.backspace)) {
						const entry = history[selectedIndex];
						if (entry) {
							deleteFromHistory(entry.id);
							history.splice(selectedIndex, 1);
							if (selectedIndex >= history.length) selectedIndex = Math.max(0, history.length - 1);
							if (history.length === 0) { done({ action: "cancel" }); return; }
							refresh();
						}
						return;
					}

					if (data === "c" || data === "C") { confirmClear = true; refresh(); return; }

					if (matchesKey(data, Key.up) || data === "k") {
						selectedIndex = Math.max(0, selectedIndex - 1);
						if (selectedIndex < scrollOffset) scrollOffset = selectedIndex;
						refresh(); return;
					}

					if (matchesKey(data, Key.down) || data === "j") {
						selectedIndex = Math.min(history.length - 1, selectedIndex + 1);
						if (selectedIndex >= scrollOffset + maxVisible) scrollOffset = selectedIndex - maxVisible + 1;
						refresh(); return;
					}

					if (matchesKey(data, Key.pageUp)) {
						selectedIndex = Math.max(0, selectedIndex - maxVisible);
						scrollOffset = Math.max(0, scrollOffset - maxVisible);
						refresh(); return;
					}

					if (matchesKey(data, Key.pageDown)) {
						selectedIndex = Math.min(history.length - 1, selectedIndex + maxVisible);
						scrollOffset = Math.min(Math.max(0, history.length - maxVisible), scrollOffset + maxVisible);
						refresh(); return;
					}

					if (matchesKey(data, Key.home)) { selectedIndex = 0; scrollOffset = 0; refresh(); return; }
					if (matchesKey(data, Key.end)) {
						selectedIndex = history.length - 1;
						scrollOffset = Math.max(0, history.length - maxVisible);
						refresh(); return;
					}
				}

				function render(width: number): string[] {
					if (cachedLines) return cachedLines;

					const lines: string[] = [];
					const boxWidth = Math.min(90, width - 4);
					const innerWidth = boxWidth - 4;

					function topBorder(title: string) {
						const titleLen = title.replace(/[^\x20-\x7E]/g, " ").length;
						return theme.fg("accent", "╭") + theme.fg("accent", theme.bold(title)) + theme.fg("accent", "─".repeat(boxWidth - 2 - titleLen) + "╮");
					}
					function bottomBorder() { return theme.fg("accent", "╰" + "─".repeat(boxWidth - 2) + "╯"); }
					function divider() { return theme.fg("accent", "├" + "─".repeat(boxWidth - 2) + "┤"); }
					function row(content: string) {
						const contentLen = content.replace(/\x1b\[[0-9;]*m/g, "").length;
						return theme.fg("accent", "│ ") + content + " ".repeat(Math.max(0, innerWidth - contentLen)) + theme.fg("accent", " │");
					}

					lines.push("");
					lines.push(topBorder(" Request History "));
					lines.push(row(theme.fg("dim", `(${history.length} request${history.length !== 1 ? "s" : ""})`)));
					lines.push(divider());

					if (confirmClear) {
						lines.push(row(""));
						lines.push(row(theme.fg("warning", "  Clear all history? ") + theme.fg("dim", "(y/n)")));
						lines.push(row(""));
						lines.push(bottomBorder());
						cachedLines = lines;
						return lines;
					}

					if (showDetails && history[selectedIndex]) {
						const entry = history[selectedIndex];
						const date = new Date(entry.timestamp);
						lines.push(row(theme.fg("text", theme.bold("  " + entry.method + " ") + entry.url)));
						lines.push(row(""));
						lines.push(row(theme.fg("muted", "  Date: ") + date.toLocaleString()));
						if (entry.template) lines.push(row(theme.fg("muted", "  Template: ") + entry.template));
						if (entry.headers && Object.keys(entry.headers).length > 0) {
							lines.push(row("")); lines.push(row(theme.fg("muted", "  Headers:")));
							for (const [k, v] of Object.entries(entry.headers)) {
								const headerLine = `    ${k}: ${v}`;
								lines.push(row(theme.fg("dim", headerLine.length > innerWidth - 2 ? headerLine.slice(0, innerWidth - 5) + "..." : headerLine)));
							}
						}
						if (entry.body) {
							lines.push(row("")); lines.push(row(theme.fg("muted", "  Body:")));
							try {
								const pretty = JSON.stringify(JSON.parse(entry.body), null, 2).split("\n");
								for (const line of pretty.slice(0, 10)) {
									lines.push(row(theme.fg("dim", "    " + (line.length > innerWidth - 4 ? line.slice(0, innerWidth - 7) + "..." : line))));
								}
								if (pretty.length > 10) lines.push(row(theme.fg("dim", `    ... ${pretty.length - 10} more lines`)));
							} catch {
								lines.push(row(theme.fg("dim", "    " + (entry.body.length > innerWidth - 4 ? entry.body.slice(0, innerWidth - 7) + "..." : entry.body))));
							}
						}
						lines.push(divider());
						lines.push(row(theme.fg("muted", "Enter") + theme.fg("dim", " replay  ") + theme.fg("muted", "d") + theme.fg("dim", " back  ") + theme.fg("muted", "Esc") + theme.fg("dim", " close")));
						lines.push(bottomBorder());
						lines.push("");
						cachedLines = lines;
						return lines;
					}

					const visibleHistory = history.slice(scrollOffset, scrollOffset + maxVisible);
					for (let i = 0; i < visibleHistory.length; i++) {
						const entry = visibleHistory[i];
						const actualIndex = scrollOffset + i;
						const isSelected = actualIndex === selectedIndex;
						const date = new Date(entry.timestamp);
						const timeStr = date.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
						const dateStr = date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
						const methodColors: Record<string, string> = { GET: "success", POST: "accent", PUT: "warning", PATCH: "warning", DELETE: "error" };
						const methodStr = theme.fg(methodColors[entry.method] as any || "text", entry.method.padEnd(6));
						const maxUrlLen = innerWidth - 30;
						const url = entry.template ? `[${entry.template}]` : entry.url;
						const truncatedUrl = url.length > maxUrlLen ? url.slice(0, maxUrlLen - 3) + "..." : url;
						const timestamp = theme.fg("dim", `${dateStr} ${timeStr}`);
						const prefix = isSelected ? theme.fg("warning", "▸ ") : "  ";
						const urlText = isSelected ? theme.fg("text", truncatedUrl) : theme.fg("muted", truncatedUrl);
						lines.push(row(prefix + methodStr + " " + urlText.padEnd(maxUrlLen) + "  " + timestamp));
					}

					if (history.length > maxVisible) {
						lines.push(row(theme.fg("dim", `  ${scrollOffset + 1}-${Math.min(scrollOffset + maxVisible, history.length)} of ${history.length}`)));
					}

					lines.push(divider());
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

			if (result.action === "cancel") return;
			if (result.action === "clear") { ctx.ui.notify("History cleared", "info"); return; }

			if (result.action === "replay" && result.entry) {
				const entry = result.entry;
				config = loadConfig(ctx.cwd);

				let task = `${entry.method} ${entry.url}`;
				if (entry.body) task += ` with body ${entry.body}`;
				if (entry.headers && Object.keys(entry.headers).length > 0) {
					task += ` with headers: ${Object.entries(entry.headers).map(([k, v]) => `${k}: ${v}`).join(", ")}`;
				}

				addToHistory({ method: entry.method, url: entry.url, body: entry.body, headers: entry.headers, template: entry.template });
				pi.sendUserMessage(`Use subagent api-tester to test: ${task}`);
			}
		},
	});

	// Input transformer
	pi.on("input", async (event) => {
		const text = event.text.trim();
		const patterns = [
			/^use\s+send-request\s+skill\s+(?:with|to)\s+(.+)$/i,
			/^use\s+send-request\s+(?:with|to)\s+(.+)$/i,
			/^send-request\s+skill[:\s]+(.+)$/i,
		];

		for (const pattern of patterns) {
			const match = text.match(pattern);
			if (match) return { action: "transform" as const, text: `/skill:send-request ${match[1].trim()}` };
		}
		return { action: "continue" as const };
	});

	// Session start
	pi.on("session_start", async (_event, ctx) => {
		config = loadConfig(ctx.cwd);
		if (config.templates?.length || config.defaults?.baseUrl) {
			ctx.ui.setStatus("super-curl", "🌐");
		}
	});
}
