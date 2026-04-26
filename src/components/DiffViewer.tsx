import type { PatchExplanation } from "../types";

interface Props {
  diff: string;
  explanations?: PatchExplanation[];
}

export function DiffViewer({ diff, explanations = [] }: Props) {
  if (!diff) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400 text-sm">
        패치 후 diff가 여기에 표시됩니다
      </div>
    );
  }

  const lines = diff.split("\n");

  return (
    <div className="overflow-auto h-full bg-gray-950">
      {explanations.length > 0 && (
        <div className="bg-gray-900 border-b border-gray-800 p-4 grid gap-3">
          {explanations.map((explanation, index) => (
            <div key={`${explanation.file}-${explanation.rule_id}-${explanation.line}-${index}`} className="rounded-xl bg-gray-800/80 border border-gray-700 p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-200">
                  {explanation.rule_name}
                </span>
                <span className="text-[11px] text-gray-400">
                  {explanation.file.split(/[\\/]/).pop()}:{explanation.line}
                </span>
              </div>
              <p className="text-sm font-semibold text-gray-100">{explanation.title}</p>
              <p className="text-xs text-gray-300 mt-1 leading-relaxed">{explanation.summary}</p>
            </div>
          ))}
        </div>
      )}
      <div className="font-mono text-xs leading-6">
        {lines.map((line, i) => {
          let cls = "text-gray-400";
          if (line.startsWith("---") || line.startsWith("+++")) cls = "text-blue-400 font-semibold";
          else if (line.startsWith("@@")) cls = "text-purple-400 bg-purple-950/30";
          else if (line.startsWith("-")) cls = "bg-red-950/50 text-red-300";
          else if (line.startsWith("+")) cls = "bg-green-950/50 text-green-300";
          return (
            <div key={i} className={`px-4 py-0.5 ${cls} whitespace-pre`}>
              {line || " "}
            </div>
          );
        })}
      </div>
    </div>
  );
}
