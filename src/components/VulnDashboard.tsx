import type { SLARule, Violation, Severity } from "../types";

interface Props {
  rules: SLARule[];
  violations: Violation[];
  onViolationClick: (v: Violation) => void;
}

const SEVERITY_CONFIG: Record<Severity, { label: string; bg: string; border: string; badge: string; dot: string }> = {
  critical: {
    label: "🔴 위험",
    bg: "bg-red-50",
    border: "border-red-200",
    badge: "bg-red-100 text-red-700",
    dot: "bg-red-500",
  },
  high: {
    label: "🟠 주의",
    bg: "bg-orange-50",
    border: "border-orange-200",
    badge: "bg-orange-100 text-orange-700",
    dot: "bg-orange-500",
  },
  medium: {
    label: "🟡 참고",
    bg: "bg-yellow-50",
    border: "border-yellow-200",
    badge: "bg-yellow-100 text-yellow-700",
    dot: "bg-yellow-500",
  },
};

function VulnCard({ rule, violation, onClick }: { rule: SLARule; violation: Violation; onClick: () => void }) {
  const cfg = SEVERITY_CONFIG[rule.severity];
  const filename = violation.file.split("/").pop() ?? violation.file;

  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-xl border ${cfg.border} ${cfg.bg} p-4 hover:brightness-95 transition-all`}
    >
      <div className="flex items-start gap-3">
        <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${cfg.dot}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${cfg.badge}`}>
              {rule.name}
            </span>
            <span className="text-xs font-mono text-gray-500">
              {filename}:{violation.line}
            </span>
          </div>
          <p className="text-sm text-gray-800 font-medium leading-snug">
            {violation.explanation}
          </p>
          {violation.code_snippet && (
            <pre className="mt-2 text-xs bg-white/70 rounded-lg p-2 font-mono text-gray-600 overflow-x-auto whitespace-pre-wrap">
              {violation.code_snippet}
            </pre>
          )}
        </div>
      </div>
    </button>
  );
}

export function VulnDashboard({ rules, violations, onViolationClick }: Props) {
  const ruleMap = Object.fromEntries(rules.map(r => [r.id, r]));

  const bySeverity: Record<Severity, Array<{ rule: SLARule; v: Violation }>> = {
    critical: [],
    high: [],
    medium: [],
  };

  for (const v of violations) {
    const rule = ruleMap[v.rule_id];
    if (!rule) continue;
    bySeverity[rule.severity].push({ rule, v });
  }

  if (violations.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <div className="text-5xl">✅</div>
        <p className="text-lg font-bold text-green-700">보안 위험 없음</p>
        <p className="text-sm text-gray-400">선택한 파일에서 위험 요소를 찾지 못했어요</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {(["critical", "high", "medium"] as Severity[]).map(sev => {
        const items = bySeverity[sev];
        if (items.length === 0) return null;
        const cfg = SEVERITY_CONFIG[sev];
        return (
          <section key={sev}>
            <div className="flex items-center gap-2 mb-3">
              <h2 className="text-sm font-bold text-gray-700">{cfg.label}</h2>
              <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${cfg.badge}`}>
                {items.length}건
              </span>
            </div>
            <div className="flex flex-col gap-2">
              {items.map(({ rule, v }, i) => (
                <VulnCard
                  key={`${v.file}-${v.line}-${i}`}
                  rule={rule}
                  violation={v}
                  onClick={() => onViolationClick(v)}
                />
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}
