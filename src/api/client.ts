import type { AIChoice, SLARule, Violation, ScanResult, PatchResult } from "../types";

const BASE_URL = "http://127.0.0.1:18765";
const AI_CLI_KEY = "SLAYER_AI_CLI";
const VALID_AI_CHOICES = new Set(["auto", "claude", "codex", "gemini"]);

function getApiKey(): string {
  return localStorage.getItem("ANTHROPIC_API_KEY") ?? "";
}

export function getAiCli(): AIChoice {
  const value = localStorage.getItem(AI_CLI_KEY) ?? "auto";
  return VALID_AI_CHOICES.has(value) ? (value as AIChoice) : "auto";
}

function headers(): HeadersInit {
  return {
    "Content-Type": "application/json",
    "X-API-Key": getApiKey(),
    "X-AI-CLI": getAiCli(),
  };
}

async function request<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(body),
  });
  if (res.status === 401) throw new Error("API_KEY_MISSING");
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new Error(body?.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

export async function parseSLA(nlRules: string): Promise<{ rules: SLARule[] }> {
  return request("/api/sla/parse", { nl_rules: nlRules });
}

export async function scanFiles(files: string[], rules: SLARule[]): Promise<ScanResult> {
  return request("/api/scan", { files, rules });
}

export async function patchFiles(
  files: string[],
  violations: Violation[],
  rules: SLARule[],
  aiCli: AIChoice = getAiCli()
): Promise<PatchResult> {
  return request("/api/patch", { files, violations, rules, ai_cli: aiCli });
}

export function saveApiKey(key: string) {
  localStorage.setItem("ANTHROPIC_API_KEY", key);
}

export function hasApiKey(): boolean {
  return !!getApiKey();
}

export function saveAiCli(aiCli: AIChoice) {
  localStorage.setItem(AI_CLI_KEY, aiCli);
}
