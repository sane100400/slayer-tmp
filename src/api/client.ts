import type { SLARule, Violation, ScanResult, PatchResult } from "../types";

const BASE_URL = "http://127.0.0.1:18765";

function getApiKey(): string {
  return localStorage.getItem("ANTHROPIC_API_KEY") ?? "";
}

function headers(): HeadersInit {
  return { "Content-Type": "application/json", "X-API-Key": getApiKey() };
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
  rules: SLARule[]
): Promise<PatchResult> {
  return request("/api/patch", { files, violations, rules });
}

export function saveApiKey(key: string) {
  localStorage.setItem("ANTHROPIC_API_KEY", key);
}

export function hasApiKey(): boolean {
  return !!getApiKey();
}
