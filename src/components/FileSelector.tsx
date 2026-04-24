import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { FolderOpen, FileCode, FolderInput } from "lucide-react";

interface Props {
  selectedFiles: string[];
  activeFile: string | null;
  onFilesChange: (files: string[]) => void;
  onFileClick: (file: string) => void;
}

export function FileSelector({ selectedFiles, activeFile, onFilesChange, onFileClick }: Props) {
  const [manualPath, setManualPath] = useState("");
  const [error, setError] = useState("");

  async function loadPath(path: string) {
    if (!path.trim()) return;
    setError("");
    try {
      const files = await invoke<string[]>("list_py_files", { dir: path.trim() });
      if (files.length === 0) {
        setError("Python 파일(.py)을 찾을 수 없어요");
      } else {
        onFilesChange(files);
      }
    } catch (e: any) {
      setError(`경로 오류: ${e}`);
    }
  }

  async function handleDialogSelect() {
    try {
      const path = await invoke<string | null>("pick_path");
      if (path) {
        setManualPath(path);
        await loadPath(path);
      }
    } catch {
      // dialog failed — let user type manually
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <button
        onClick={handleDialogSelect}
        className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold px-4 py-2.5 rounded-lg transition-colors w-full justify-center"
      >
        <FolderOpen size={18} />
        폴더 / 파일 선택
      </button>

      {/* 경로 직접 입력 */}
      <div className="flex gap-1.5">
        <input
          type="text"
          value={manualPath}
          onChange={(e) => setManualPath(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && loadPath(manualPath)}
          placeholder="/home/user/myproject"
          className="flex-1 border border-gray-300 rounded-lg px-3 py-1.5 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 min-w-0"
        />
        <button
          onClick={() => loadPath(manualPath)}
          className="shrink-0 bg-gray-100 hover:bg-gray-200 text-gray-700 px-2.5 py-1.5 rounded-lg transition-colors"
          title="경로 불러오기"
        >
          <FolderInput size={15} />
        </button>
      </div>

      {error && <p className="text-xs text-red-500">{error}</p>}

      {selectedFiles.length === 0 ? (
        <p className="text-xs text-gray-400 text-center py-2">선택된 파일 없음</p>
      ) : (
        <div className="flex flex-col gap-0.5 max-h-44 overflow-y-auto">
          <p className="text-xs text-gray-400 mb-1">{selectedFiles.length}개 파일 선택됨</p>
          {selectedFiles.map((f) => {
            const name = f.split("/").pop() ?? f;
            return (
              <button
                key={f}
                onClick={() => onFileClick(f)}
                className={`flex items-center gap-2 text-left px-2.5 py-1.5 rounded-md text-xs transition-colors ${
                  activeFile === f
                    ? "bg-blue-100 text-blue-700 font-medium"
                    : "hover:bg-gray-100 text-gray-600"
                }`}
              >
                <FileCode size={13} className="shrink-0 text-gray-400" />
                <span className="truncate" title={f}>{name}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
