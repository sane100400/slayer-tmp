import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Shield, ScanLine, Loader2, Settings } from "lucide-react";
import { scanFiles, patchFiles, hasApiKey } from "./api/client";
import { FileSelector } from "./components/FileSelector";
import { VulnDashboard } from "./components/VulnDashboard";
import { CodeViewer } from "./components/CodeViewer";
import { DiffViewer } from "./components/DiffViewer";
import { DeployGate } from "./components/DeployGate";
import { SettingsModal } from "./components/SettingsModal";
import type { AppState, SLARule, ScanResult, Violation } from "./types";

// 규칙은 사용자가 볼 필요 없음 — 자동으로 적용
const PRESET_RULES: SLARule[] = [
  { id: "r1", name: "데이터베이스 해킹 위험", raw_nl: "sql injection", rule_type: "SQL_INJECTION", severity: "critical",
    description: "누군가 입력창에 특수문자를 넣어 DB의 모든 회원정보를 훔쳐갈 수 있어요." },
  { id: "r2", name: "비밀번호·키 코드 노출", raw_nl: "hardcoded secrets", rule_type: "HARDCODED_SECRETS", severity: "critical",
    description: "코드에 적힌 비밀번호·API 키가 GitHub에 올리는 순간 모두 공개돼요." },
  { id: "r3", name: "서버 명령어 탈취 위험", raw_nl: "command injection", rule_type: "COMMAND_INJECTION", severity: "critical",
    description: "사용자 입력이 서버 명령어로 실행되어 서버 전체를 원격 조종당할 수 있어요." },
  { id: "r4", name: "디버그 모드 배포", raw_nl: "debug mode on", rule_type: "DEBUG_MODE_ON", severity: "high",
    description: "에러 시 서버 내부 코드·경로·환경변수가 사용자 화면에 그대로 노출돼요." },
  { id: "r5", name: "로그인 쿠키 탈취 위험", raw_nl: "insecure cookie", rule_type: "INSECURE_COOKIE", severity: "high",
    description: "보안 옵션 없는 쿠키는 악성 광고 배너 하나로 해커가 훔쳐갈 수 있어요." },
  { id: "r6", name: "비밀번호 1초 해독 위험", raw_nl: "weak hash md5 sha1", rule_type: "WEAK_HASH", severity: "high",
    description: "MD5·SHA1 해시는 요즘 컴퓨터로 1초도 안 걸려 해독돼요. DB 유출 시 전원 노출됩니다." },
  { id: "r7", name: "피싱 사이트 유도 가능", raw_nl: "open redirect", rule_type: "OPEN_REDIRECT", severity: "medium",
    description: "공격자가 로그인 후 이동 URL을 조작해 피싱 사이트로 사용자를 속일 수 있어요." },
];

type RightTab = "vulns" | "code" | "diff";

const INIT: AppState = {
  step: "idle", selectedFiles: [], rules: PRESET_RULES,
  scanResult: null, patchResult: null, activeFile: null, apiKeyMissing: false,
};

export default function App() {
  const [state, setState] = useState<AppState>(INIT);
  const [rightTab, setRightTab] = useState<RightTab>("vulns");
  const [highlightLine, setHighlightLine] = useState<number | null>(null);
  const [activeFileCode, setActiveFileCode] = useState("");
  const [showSettings, setShowSettings] = useState(false);

  const scanning = state.step === "scanning";
  const patching = state.step === "patching";

  async function handleScan() {
    if (state.selectedFiles.length === 0) return;
    setState(s => ({ ...s, step: "scanning", scanResult: null, patchResult: null }));
    try {
      const result = await scanFiles(state.selectedFiles, PRESET_RULES);
      setState(s => ({ ...s, scanResult: result, step: "scanned" }));
      setRightTab("vulns");
    } catch {
      setState(s => ({ ...s, step: "idle" }));
    }
  }

  async function handlePatch() {
    if (!state.scanResult) return;
    if (!hasApiKey()) { setShowSettings(true); return; }
    setState(s => ({ ...s, step: "patching" }));
    try {
      const violatedFiles = [...new Set(
        state.scanResult!.violations.filter(v => v.rule_id !== "__file_error__").map(v => v.file)
      )];
      const result = await patchFiles(violatedFiles, state.scanResult!.violations, PRESET_RULES);

      // 백엔드가 이미 재스캔했으므로 remaining_violations로 scanResult 업데이트
      const failIds = new Set(
        result.remaining_violations.filter(v => v.rule_id !== "__file_error__").map(v => v.rule_id)
      );
      const passCount = PRESET_RULES.filter(r => !failIds.has(r.id)).length;
      const updatedScan: ScanResult = {
        rules: state.scanResult!.rules,
        violations: result.remaining_violations,
        pass_count: passCount,
        fail_count: PRESET_RULES.length - passCount,
        deployable: result.deployable,
      };

      setState(s => ({ ...s, patchResult: result, scanResult: updatedScan, step: "patched" }));
      setRightTab("diff");
    } catch (e: any) {
      if (e.message === "API_KEY_MISSING") setShowSettings(true);
      setState(s => ({ ...s, step: "scanned" }));
    }
  }

  async function handleViolationClick(v: Violation) {
    setHighlightLine(v.line);
    if (state.activeFile !== v.file) {
      setState(s => ({ ...s, activeFile: v.file }));
      try {
        const code = await invoke<string>("read_file", { path: v.file });
        setActiveFileCode(code);
      } catch {}
    }
    setRightTab("code");
  }

  async function handleFileClick(file: string) {
    setState(s => ({ ...s, activeFile: file }));
    setHighlightLine(null);
    try {
      const code = await invoke<string>("read_file", { path: file });
      setActiveFileCode(code);
    } catch {}
    setRightTab("code");
  }

  const violations = state.scanResult?.violations.filter(v => v.rule_id !== "__file_error__") ?? [];
  const failCount = state.scanResult?.fail_count ?? 0;

  return (
    <div className="flex flex-col h-screen bg-gray-50" style={{ fontFamily: "'Noto Sans KR', sans-serif" }}>
      {/* Header */}
      <header className="flex items-center justify-between px-5 py-3 bg-white border-b border-gray-200">
        <div className="flex items-center gap-2">
          <Shield size={22} className="text-blue-600" />
          <span className="text-lg font-bold text-gray-900">SLAyer</span>
          <span className="text-xs bg-blue-50 text-blue-600 px-2 py-0.5 rounded-full ml-1">보안 자동 패치</span>
        </div>
        <button onClick={() => setShowSettings(true)} className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-700">
          <Settings size={15} /> 설정
        </button>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Left Panel */}
        <div className="w-72 shrink-0 flex flex-col gap-4 p-4 bg-white border-r border-gray-200 overflow-y-auto">
          {/* 파일 선택 */}
          <FileSelector
            selectedFiles={state.selectedFiles}
            activeFile={state.activeFile}
            onFilesChange={(files) => setState(s => ({ ...s, selectedFiles: files, scanResult: null, patchResult: null, step: "idle" }))}
            onFileClick={handleFileClick}
          />

          {/* 스캔 버튼 */}
          <button
            onClick={handleScan}
            disabled={state.selectedFiles.length === 0 || scanning || patching}
            className="flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 text-white font-bold py-3 rounded-xl transition-colors"
          >
            {scanning ? <Loader2 size={18} className="animate-spin" /> : <ScanLine size={18} />}
            {scanning ? "스캔 중…" : "보안 스캔 시작"}
          </button>

          {/* 스캔 결과 요약 */}
          {state.scanResult && (
            <>
              <div className="bg-gray-50 rounded-xl p-3 text-sm">
                {failCount === 0 ? (
                  <p className="text-green-600 font-semibold text-center">✅ 위험 요소 없음</p>
                ) : (
                  <p className="text-gray-700">
                    <span className="font-bold text-red-600">{violations.length}개</span>의 보안 위험 발견
                  </p>
                )}
              </div>

              {failCount > 0 && (
                <button
                  onClick={handlePatch}
                  disabled={patching}
                  className="flex items-center justify-center gap-2 bg-amber-500 hover:bg-amber-600 disabled:bg-gray-300 text-white font-bold py-3 rounded-xl transition-colors"
                >
                  {patching ? <Loader2 size={18} className="animate-spin" /> : "⚡"}
                  {patching ? "Claude가 고치는 중…" : "전부 자동 패치"}
                </button>
              )}

              <DeployGate
                deployable={state.scanResult.deployable}
                failCount={failCount}
              />
            </>
          )}
        </div>

        {/* Right Panel */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="flex border-b border-gray-200 bg-white">
            {(["vulns", "code", "diff"] as RightTab[]).map(tab => (
              <button
                key={tab}
                onClick={() => setRightTab(tab)}
                className={`px-5 py-3 text-sm font-medium transition-colors border-b-2 ${
                  rightTab === tab ? "border-blue-600 text-blue-600" : "border-transparent text-gray-500 hover:text-gray-700"
                }`}
              >
                {tab === "vulns" ? `위험 요소${violations.length > 0 ? ` (${violations.length})` : ""}` : tab === "code" ? "코드" : "수정 내역"}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-hidden">
            {rightTab === "vulns" && (
              <div className="h-full overflow-y-auto p-4">
                {!state.scanResult ? (
                  <div className="flex flex-col items-center justify-center h-full text-gray-300 gap-4">
                    <Shield size={64} />
                    <div className="text-center">
                      <p className="text-gray-500 font-medium">파일을 선택하고 보안 스캔을 시작하세요</p>
                      <p className="text-sm text-gray-400 mt-1">SQL 인젝션, 비밀번호 노출 등 7가지 위험을 자동 탐지합니다</p>
                    </div>
                  </div>
                ) : (
                  <VulnDashboard
                    rules={PRESET_RULES}
                    violations={violations}
                    onViolationClick={handleViolationClick}
                  />
                )}
              </div>
            )}
            {rightTab === "code" && (
              <div className="h-full">
                {!state.activeFile || !activeFileCode ? (
                  <div className="flex items-center justify-center h-full text-gray-400 text-sm">
                    위험 항목을 클릭하면 해당 코드로 이동합니다
                  </div>
                ) : (
                  <CodeViewer
                    file={state.activeFile}
                    code={activeFileCode}
                    violations={violations.filter(v => v.file === state.activeFile)}
                    highlightLine={highlightLine}
                  />
                )}
              </div>
            )}
            {rightTab === "diff" && (
              <div className="h-full">
                <DiffViewer diff={state.patchResult?.diff ?? ""} />
              </div>
            )}
          </div>
        </div>
      </div>

      {showSettings && <SettingsModal onSave={() => setShowSettings(false)} />}
    </div>
  );
}
