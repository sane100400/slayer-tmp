import { Loader2, Zap } from "lucide-react";

const CHIPS = [
  "외부 네트워크 호출 없음",
  "shell 명령어 실행 없음",
  "하드코딩된 비밀번호/API 키 없음",
  "SQL 쿼리에 사용자 입력 직접 삽입 없음",
];

interface Props {
  value: string;
  onChange: (v: string) => void;
  onParse: () => void;
  loading: boolean;
  disabled: boolean;
}

export function SLAInput({ value, onChange, onParse, loading, disabled }: Props) {
  function addChip(chip: string) {
    const lines = value.trim() ? value.trim().split("\n") : [];
    if (!lines.includes(chip)) {
      onChange(lines.concat(chip).join("\n"));
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <label className="text-sm font-semibold text-gray-700">보안 규칙 (자연어)</label>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={"보안 규칙을 한 줄씩 입력하세요\n빈칸이면 기본 4개 규칙 자동 적용"}
        rows={4}
        className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
      />
      <div className="flex flex-wrap gap-1.5">
        {CHIPS.map((chip) => (
          <button
            key={chip}
            onClick={() => addChip(chip)}
            className="text-xs bg-gray-100 hover:bg-gray-200 text-gray-600 px-2.5 py-1 rounded-full transition-colors"
          >
            + {chip}
          </button>
        ))}
      </div>
      <button
        onClick={onParse}
        disabled={loading || disabled}
        className="flex items-center justify-center gap-2 bg-violet-600 hover:bg-violet-700 disabled:bg-gray-300 text-white font-semibold py-2 rounded-lg transition-colors"
      >
        {loading ? <Loader2 size={16} className="animate-spin" /> : <Zap size={16} />}
        {loading ? "분석 중…" : "규칙 파싱"}
      </button>
    </div>
  );
}
