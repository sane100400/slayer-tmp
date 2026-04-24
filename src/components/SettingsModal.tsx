import { useState } from "react";
import { saveApiKey } from "../api/client";

interface Props {
  onSave: () => void;
}

export function SettingsModal({ onSave }: Props) {
  const [key, setKey] = useState("");

  function handleSave() {
    if (!key.trim()) return;
    saveApiKey(key.trim());
    onSave();
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md">
        <h2 className="text-xl font-bold text-gray-900 mb-2">API 키 설정</h2>
        <p className="text-sm text-gray-500 mb-6">
          Claude API를 사용하려면 Anthropic API 키가 필요합니다.
          <a href="https://console.anthropic.com" target="_blank" rel="noreferrer" className="text-blue-500 underline ml-1">
            키 발급 →
          </a>
        </p>
        <input
          type="password"
          placeholder="sk-ant-..."
          value={key}
          onChange={(e) => setKey(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSave()}
          className="w-full border border-gray-300 rounded-lg px-4 py-2 text-sm font-mono mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          onClick={handleSave}
          disabled={!key.trim()}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 text-white font-semibold py-2 rounded-lg transition-colors"
        >
          저장하고 계속
        </button>
      </div>
    </div>
  );
}
