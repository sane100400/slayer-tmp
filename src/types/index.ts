export type RuleType =
  | "NO_NETWORK"
  | "NO_EXEC"
  | "NO_HARDCODED_SECRETS"
  | "SQL_PARAM_BINDING"
  | "NO_DEBUG_MODE"
  | "NO_INSECURE_HASH"
  | "NO_BARE_EXCEPT"
  | "CUSTOM";

export type Severity = "critical" | "high" | "medium";
export type AIChoice = "auto" | "claude" | "codex" | "gemini";

export interface SLARule {
  id: string;
  name: string;
  description: string;
  raw_nl: string;
  rule_type: RuleType;
  severity: Severity;
}

export interface Violation {
  rule_id: string;
  file: string;
  line: number;
  col: number;
  code_snippet: string;
  explanation: string;
}

export interface ScanResult {
  rules: SLARule[];
  violations: Violation[];
  pass_count: number;
  fail_count: number;
  deployable: boolean;
}

export interface PatchExplanation {
  file: string;
  rule_id: string;
  rule_name: string;
  line: number;
  title: string;
  summary: string;
  reference: string;
}

export interface PatchResult {
  original_code: string;
  patched_code: string;
  diff: string;
  patch_explanations: PatchExplanation[];
  remaining_violations: Violation[];
  deployable: boolean;
  ai_used: string;
  patch_explanations?: PatchExplanation[];
}

export interface PatchExplanation {
  file: string;
  rule_id: string;
  rule_name: string;
  line: number;
  title: string;
  summary: string;
  guidance: string;
  reference: string;
}

export type AppStep =
  | "idle"
  | "rules_parsed"
  | "scanning"
  | "scanned"
  | "patching"
  | "patched";

export interface AppState {
  step: AppStep;
  selectedFiles: string[];
  rules: SLARule[];
  scanResult: ScanResult | null;
  patchResult: PatchResult | null;
  activeFile: string | null;
  apiKeyMissing: boolean;
}
