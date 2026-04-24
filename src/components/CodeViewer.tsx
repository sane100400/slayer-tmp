import { useEffect, useRef } from "react";
import type { Violation } from "../types";

interface Props {
  file: string;
  code: string;
  violations: Violation[];
  highlightLine: number | null;
}

export function CodeViewer({ file, code, violations, highlightLine }: Props) {
  const lineRefs = useRef<Record<number, HTMLDivElement | null>>({});
  const violatedLines = new Set(violations.map(v => v.line));
  const violationMap: Record<number, string> = {};
  for (const v of violations) violationMap[v.line] = v.explanation;

  useEffect(() => {
    if (highlightLine && lineRefs.current[highlightLine]) {
      lineRefs.current[highlightLine]?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [highlightLine]);

  const lines = code.split("\n");

  return (
    <div className="flex flex-col h-full">
      <div className="px-4 py-2 bg-gray-100 border-b border-gray-200 text-xs font-mono text-gray-500 truncate">
        {file}
      </div>
      <div className="flex-1 overflow-auto bg-gray-950 font-mono text-xs leading-6">
        {lines.map((line, i) => {
          const lineno = i + 1;
          const isViolated = violatedLines.has(lineno);
          const isHighlighted = lineno === highlightLine;
          return (
            <div
              key={lineno}
              ref={(el) => { lineRefs.current[lineno] = el; }}
              title={isViolated ? violationMap[lineno] : undefined}
              className={`flex group ${
                isHighlighted
                  ? "bg-red-900/60 border-l-2 border-red-400"
                  : isViolated
                  ? "bg-red-950/40 border-l-2 border-red-700"
                  : "border-l-2 border-transparent"
              }`}
            >
              <span className="w-12 shrink-0 text-right pr-4 text-gray-600 select-none">{lineno}</span>
              <pre className="flex-1 pr-4 text-gray-200 whitespace-pre overflow-x-visible">{line || " "}</pre>
              {isViolated && (
                <span className="shrink-0 hidden group-hover:block text-red-300 text-xs px-2 self-center max-w-xs truncate">
                  {violationMap[lineno]}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
