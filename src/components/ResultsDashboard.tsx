import { useState } from "react";
import { ChevronDown, ChevronRight, CheckCircle, XCircle, Loader2, AlertTriangle } from "lucide-react";
import type { SLARule, ScanResult, Violation } from "../types";

interface Props {
  scanResult: ScanResult;
  onViolationClick: (v: Violation) => void;
  onPatch: () => void;
  patching: boolean;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "bg-red-100 text-red-700",
  high: "bg-orange-100 text-orange-700",
  medium: "bg-yellow-100 text-yellow-700",
};

function RuleCard({ rule, violations, onViolationClick }: {
  rule: SLARule;
  violations: Violation[];
  onViolationClick: (v: Violation) => void;
}) {
  const [open, setOpen] = useState(true);
  const pass = violations.length === 0;

  if (rule.id === "__file_error__") return null;

  return (
    <div className={`border rounded-xl overflow-hidden ${pass ? "border-green-200" : "border-red-200"}`}>
      <button
        onClick={() => setOpen(!open)}
        className={`w-full flex items-center gap-3 px-4 py-3 text-left ${pass ? "bg-green-50" : "bg-red-50"}`}
      >
        {pass ? (
          <CheckCircle size={18} className="text-green-500 shrink-0" />
        ) : (
          <XCircle size={18} className="text-red-500 shrink-0" />
        )}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-sm text-gray-900">{rule.name}</span>
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${SEVERITY_COLOR[rule.severity]}`}>
              {rule.severity.toUpperCase()}
            </span>
          </div>
          <p className="text-xs text-gray-500 truncate mt-0.5">{rule.description}</p>
        </div>
        <span className={`text-xs font-semibold shrink-0 ${pass ? "text-green-600" : "text-red-600"}`}>
          {pass ? "통과" : `${violations.length}건 위반`}
        </span>
        {!pass && (open ? <ChevronDown size={14} /> : <ChevronRight size={14} />)}
      </button>

      {!pass && open && (
        <div className="divide-y divide-gray-100">
          {violations.map((v, i) => (
            <button
              key={i}
              onClick={() => onViolationClick(v)}
              className="w-full flex items-start gap-3 px-4 py-2.5 hover:bg-gray-50 text-left"
            >
              <AlertTriangle size={13} className="text-orange-400 shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="text-xs font-mono text-gray-600 truncate">
                  {v.file.split("/").pop()}:{v.line}
                </p>
                <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{v.explanation}</p>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function ResultsDashboard({ scanResult, onViolationClick, onPatch, patching }: Props) {
  const violationsByRule = (rule: SLARule) =>
    scanResult.violations.filter(v => v.rule_id === rule.id);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between text-sm text-gray-600">
        <span>룰 {scanResult.rules.length}개 · 통과 <strong className="text-green-600">{scanResult.pass_count}</strong> · 실패 <strong className="text-red-600">{scanResult.fail_count}</strong></span>
      </div>

      {scanResult.rules.map((rule) => (
        <RuleCard
          key={rule.id}
          rule={rule}
          violations={violationsByRule(rule)}
          onViolationClick={onViolationClick}
        />
      ))}

      {scanResult.fail_count > 0 && (
        <button
          onClick={onPatch}
          disabled={patching}
          className="flex items-center justify-center gap-2 mt-2 bg-amber-500 hover:bg-amber-600 disabled:bg-gray-300 text-white font-bold py-3 rounded-xl transition-colors"
        >
          {patching ? <Loader2 size={16} className="animate-spin" /> : "⚡"}
          {patching ? "Claude가 고치는 중…" : "Auto-fix All"}
        </button>
      )}
    </div>
  );
}
