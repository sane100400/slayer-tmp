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
        <div className="border-b border-gray-800 bg-gray-900 p-4">
          <p className="text-xs font-semibold text-amber-300 mb-2">패치 설명</p>
          <div className="flex flex-col gap-2">
            {explanations.map((item, i) => (
              <div key={`${item.file}-${item.line}-${item.rule_id}-${i}`} className="rounded-lg bg-gray-950/70 p-3">
                <p className="text-sm font-semibold text-gray-100">
                  {item.rule_name} · {item.file.split("/").pop()}:{item.line}
                </p>
                <p className="text-xs text-gray-300 mt-1">{item.title}</p>
                <p className="text-xs text-gray-400 mt-1 leading-relaxed">{item.summary}</p>
                <p className="text-[11px] text-gray-500 mt-1">{item.reference}</p>
              </div>
            ))}
          </div>
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
