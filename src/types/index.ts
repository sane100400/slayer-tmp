export type RuleType =
  | "SQL_INJECTION"
  | "HARDCODED_SECRETS"
  | "DEBUG_MODE_ON"
  | "INSECURE_COOKIE"
  | "WEAK_HASH"
  | "COMMAND_INJECTION"
  | "OPEN_REDIRECT"
  | "CUSTOM";

export type Severity = "critical" | "high" | "medium";

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

export interface PatchResult {
  original_code: string;
  patched_code: string;
  diff: string;
  remaining_violations: Violation[];
  deployable: boolean;
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
