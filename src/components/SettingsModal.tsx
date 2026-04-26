import { useState } from "react";
import { getAiCli, saveAiCli } from "../api/client";
import type { AIChoice } from "../types";

interface Props {
  onSave: () => void;
}

export function SettingsModal({ onSave }: Props) {
  const [aiCli, setAiCli] = useState<AIChoice>(getAiCli());

  function handleSave() {
    saveAiCli(aiCli);
    onSave();
  }

  const choices: { value: AIChoice; label: string; description: string }[] = [
    { value: "auto", label: "자동 감지", description: "PATH에서 claude → codex → gemini 순서로 사용" },
    { value: "claude", label: "Claude Code", description: "claude -p headless 모드로 패치" },
    { value: "codex", label: "Codex CLI", description: "codex exec read-only 모드로 패치" },
    { value: "gemini", label: "Gemini CLI", description: "gemini --prompt headless 모드로 패치" },
  ];

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md">
        <h2 className="text-xl font-bold text-gray-900 mb-2">AI CLI 설정</h2>
        <p className="text-sm text-gray-500 mb-6">
          패치는 로컬에 설치된 Claude, Codex, Gemini CLI 중 하나를 사용합니다.
          선택한 CLI가 PATH에 있어야 합니다.
        </p>
        <div className="flex flex-col gap-2 mb-5">
          {choices.map((choice) => (
            <label
              key={choice.value}
              className={`border rounded-xl px-4 py-3 cursor-pointer transition-colors ${
                aiCli === choice.value ? "border-blue-500 bg-blue-50" : "border-gray-200 hover:bg-gray-50"
              }`}
            >
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  name="ai-cli"
                  value={choice.value}
                  checked={aiCli === choice.value}
                  onChange={() => setAiCli(choice.value)}
                />
                <span className="font-semibold text-sm text-gray-900">{choice.label}</span>
              </div>
              <p className="text-xs text-gray-500 mt-1 ml-5">{choice.description}</p>
            </label>
          ))}
        </div>
        <button
          onClick={handleSave}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 rounded-lg transition-colors"
        >
          저장하고 계속
        </button>
      </div>
    </div>
  );
}
