interface Props {
  diff: string;
}

export function DiffViewer({ diff }: Props) {
  if (!diff) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400 text-sm">
        패치 후 diff가 여기에 표시됩니다
      </div>
    );
  }

  const lines = diff.split("\n");

  return (
    <div className="overflow-auto h-full bg-gray-950 font-mono text-xs leading-6">
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
  );
}
