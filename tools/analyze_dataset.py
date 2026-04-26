"""
Vibe Coding Dataset Pattern Analyzer (RAG Edition)

수천 개 Python 파일을 분석해 바이브코딩 7대 취약 패턴을 도출.

파이프라인:
  1. AST 분석 — 전체 파일 결정적 패턴 카운팅 (수천 개 처리 가능)
  2. 인덱싱   — ChromaDB에 코드 청크 임베딩 저장
  3. RAG 쿼리 — 각 패턴별 대표 예시 검색
  4. AI 분석  — 로컬 AI CLI로 시맨틱 인사이트 추출
  5. 리포트   — 패턴 빈도 + 7대 추천 + JSON 저장

사용법:
  pip install chromadb
  python tools/analyze_dataset.py            # AST + RAG 인덱스
  python tools/analyze_dataset.py --ai       # + AI CLI 시맨틱 분석
  python tools/analyze_dataset.py --query    # 인덱스에서 패턴 검색만
  python tools/analyze_dataset.py --top 10   # 상위 N개 출력
"""

import ast
import re
import os
import json
import argparse
import hashlib
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

DATASET_DIR = Path(__file__).parent.parent / "dataset"
INDEX_DIR   = Path(__file__).parent / ".chroma_index"
REPORT_PATH = Path(__file__).parent / "pattern_report.json"

# ── 패턴 정의 ─────────────────────────────────────────────────────────────

PATTERNS = {
    "NO_HARDCODED_SECRETS": {
        "label": "하드코딩 크레덴셜",
        "severity": "critical",
        "query": "hardcoded password api_key secret token credential",
    },
    "NO_NETWORK": {
        "label": "무제한 외부 네트워크 호출",
        "severity": "critical",
        "query": "requests.get requests.post urllib http api call external",
    },
    "NO_EXEC_SHELL": {
        "label": "위험한 shell 실행",
        "severity": "critical",
        "query": "subprocess shell=True os.system os.popen exec command injection",
    },
    "SQL_PARAM_BINDING": {
        "label": "SQL 인젝션 취약 쿼리",
        "severity": "high",
        "query": "f-string SQL SELECT INSERT execute format query injection",
    },
    "NO_DEBUG_MODE": {
        "label": "DEBUG=True 하드코딩",
        "severity": "high",
        "query": "DEBUG=True debug mode development app.run flask django",
    },
    "NO_INSECURE_HASH": {
        "label": "MD5/SHA1 패스워드 해싱",
        "severity": "high",
        "query": "hashlib md5 sha1 password hash weak encryption",
    },
    "NO_BARE_EXCEPT": {
        "label": "빈 except 블록",
        "severity": "medium",
        "query": "except pass bare except exception suppress error ignore",
    },
    "NO_EVAL": {
        "label": "eval/exec 동적 실행",
        "severity": "high",
        "query": "eval exec compile dynamic code execution dangerous",
    },
}

# ── AST 분석 ─────────────────────────────────────────────────────────────

NETWORK_IMPORTS = {
    "requests", "urllib", "urllib3", "httpx",
    "aiohttp", "socket", "websocket", "boto3",
}
NETWORK_METHODS = {"get", "post", "put", "delete", "patch", "request", "urlopen"}
EXEC_CALLS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_output", "os.system", "os.popen",
}
SECRET_REGEXES = [
    re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']'),
    re.compile(r'(?i)(api_key|apikey|api_secret)\s*=\s*["\'][^"\']{8,}["\']'),
    re.compile(r'(?i)(secret|token|auth_token)\s*=\s*["\'][^"\']{8,}["\']'),
    re.compile(r'sk-[A-Za-z0-9]{20,}'),
    re.compile(r'ghp_[A-Za-z0-9]{36}'),
    re.compile(r'(?i)aws_access_key_id\s*=\s*["\'][A-Z0-9]{16,}["\']'),
]
SQL_RE   = re.compile(r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b')
DEBUG_RE = [
    re.compile(r'(?i)^\s*DEBUG\s*=\s*True'),
    re.compile(r'app\.run\(.*debug\s*=\s*True'),
]
PASSWORD_VARS = {"password", "passwd", "pwd"}


@dataclass
class Hit:
    pattern_id: str
    file: str
    line: int
    snippet: str


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts, cur = [], func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr); cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _parent_func(tree, target):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(c is target for c in ast.walk(node)):
                return node
    return None


def _has_pwd_var(func_node) -> bool:
    return any(
        isinstance(n, ast.Name) and any(p in n.id.lower() for p in PASSWORD_VARS)
        for n in ast.walk(func_node)
    )


def ast_analyze(path: Path) -> list[Hit]:
    hits: list[Hit] = []
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return hits

    lines = source.splitlines()

    # 비-AST 패턴: 라인 스캔
    for i, line in enumerate(lines, 1):
        for rx in SECRET_REGEXES:
            if rx.search(line):
                hits.append(Hit("NO_HARDCODED_SECRETS", str(path), i, line.strip()[:120]))
        for rx in DEBUG_RE:
            if rx.search(line):
                hits.append(Hit("NO_DEBUG_MODE", str(path), i, line.strip()[:120]))

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return hits

    imported_net = set()

    for node in ast.walk(tree):
        # import 수집
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in getattr(node, "names", []):
                mod = alias.name.split(".")[0]
                if mod in NETWORK_IMPORTS:
                    imported_net.add(mod)

        if isinstance(node, ast.Call):
            name = _call_name(node)
            ln = getattr(node, "lineno", 0)
            snippet = lines[ln - 1].strip()[:120] if 0 < ln <= len(lines) else ""

            # NO_NETWORK
            if imported_net:
                func = node.func
                method = func.attr if isinstance(func, ast.Attribute) else None
                if method in NETWORK_METHODS:
                    hits.append(Hit("NO_NETWORK", str(path), ln, snippet))

            # NO_EXEC_SHELL
            if name in EXEC_CALLS:
                hits.append(Hit("NO_EXEC_SHELL", str(path), ln, snippet))
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    hits.append(Hit("NO_EXEC_SHELL", str(path), ln, snippet))

            # NO_EVAL
            if name in ("eval", "exec", "compile"):
                hits.append(Hit("NO_EVAL", str(path), ln, snippet))

            # NO_INSECURE_HASH
            if any(name.endswith(f) for f in ("md5", "sha1")):
                parent = _parent_func(tree, node)
                if parent and _has_pwd_var(parent):
                    hits.append(Hit("NO_INSECURE_HASH", str(path), ln, snippet))

        # SQL_PARAM_BINDING
        if isinstance(node, ast.JoinedStr):
            ln = getattr(node, "lineno", 0)
            if 0 < ln <= len(lines):
                snippet = lines[ln - 1].strip()[:120]
                if SQL_RE.search(snippet):
                    hits.append(Hit("SQL_PARAM_BINDING", str(path), ln, snippet))

        # NO_BARE_EXCEPT
        if isinstance(node, ast.ExceptHandler):
            is_bare = node.type is None
            is_pass = (
                isinstance(getattr(node.type, "id", None), str)
                and node.type.id == "Exception"  # type: ignore
                and len(node.body) == 1
                and isinstance(node.body[0], ast.Pass)
            )
            if is_bare or is_pass:
                ln = getattr(node, "lineno", 0)
                hits.append(Hit("NO_BARE_EXCEPT", str(path), ln,
                                lines[ln - 1].strip()[:120] if 0 < ln <= len(lines) else ""))

    return hits


# ── ChromaDB RAG 인덱서 ───────────────────────────────────────────────────

def chunk_file(path: Path, chunk_size: int = 30) -> list[tuple[str, dict]]:
    """파일을 30줄 청크로 분할. (chunk_text, metadata) 리스트 반환."""
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    lines = source.splitlines()
    chunks = []
    for start in range(0, len(lines), chunk_size):
        chunk_lines = lines[start:start + chunk_size]
        text = "\n".join(chunk_lines)
        if len(text.strip()) < 20:
            continue
        doc_id = hashlib.md5(f"{path}:{start}".encode()).hexdigest()
        chunks.append((text, {"file": str(path), "start_line": start + 1, "doc_id": doc_id}))
    return chunks


def build_index(py_files: list[Path], batch_size: int = 500):
    try:
        import chromadb
    except ImportError:
        print("⚠️  chromadb 없음 — pip install chromadb")
        return None

    print(f"📦 ChromaDB 인덱스 빌드 중... ({len(py_files)}개 파일)")
    client = chromadb.PersistentClient(path=str(INDEX_DIR))

    try:
        client.delete_collection("vibe_code")
    except Exception:
        pass
    collection = client.create_collection("vibe_code")

    docs, metas, ids = [], [], []
    total_chunks = 0

    for i, f in enumerate(py_files, 1):
        print(f"  [{i}/{len(py_files)}] 청킹: {f.name[:40]}", end="\r")
        for text, meta in chunk_file(f):
            docs.append(text)
            metas.append(meta)
            ids.append(meta["doc_id"])
            if len(docs) >= batch_size:
                collection.add(documents=docs, metadatas=metas, ids=ids)
                total_chunks += len(docs)
                docs, metas, ids = [], [], []

    if docs:
        collection.add(documents=docs, metadatas=metas, ids=ids)
        total_chunks += len(docs)

    print(f"\n  ✓ 인덱스 완료: {total_chunks}개 청크 저장 → {INDEX_DIR}")
    return collection


def rag_query(collection, pattern_id: str, n_results: int = 5) -> list[dict]:
    """특정 패턴의 대표 코드 예시를 RAG로 검색."""
    query = PATTERNS[pattern_id]["query"]
    try:
        results = collection.query(query_texts=[query], n_results=n_results)
        hits = []
        for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
            hits.append({"snippet": doc[:300], "file": meta["file"], "line": meta["start_line"]})
        return hits
    except Exception:
        return []


# ── AI CLI 분석 ───────────────────────────────────────────────────────────

AI_CANDIDATES = [
    {"name": "claude", "check": ["claude", "--version"], "run": ["claude", "-p"]},
    {"name": "codex",  "check": ["codex",  "--version"], "run": ["codex",  "exec"]},
    {"name": "gemini", "check": ["gemini", "--version"], "run": ["gemini"]},
]


def detect_ai() -> Optional[dict]:
    import subprocess
    for c in AI_CANDIDATES:
        try:
            if subprocess.run(c["check"], capture_output=True, timeout=5).returncode == 0:
                return c
        except (FileNotFoundError, Exception):
            continue
    return None


def ai_analyze_pattern(ai_cli: dict, pattern_id: str, examples: list[dict]) -> str:
    import subprocess
    label = PATTERNS[pattern_id]["label"]
    samples = "\n\n".join(
        f"# {e['file'].split('/')[-1]}:{e['line']}\n{e['snippet'][:400]}"
        for e in examples[:5]
    )
    prompt = f"""다음은 실제 AI 바이브코딩 결과물에서 '{label}' 패턴이 발견된 코드 예시입니다.

{samples}

다음 질문에 JSON으로만 답하세요 (설명, 마크다운 없이):
{{
  "pattern_id": "{pattern_id}",
  "why_common": "왜 바이브코딩에서 자주 나타나는지 (1문장 한국어)",
  "risk": "실제 보안 위험 (1문장 한국어)",
  "patch_hint": "가장 간단한 수정 방법 (코드 1줄)",
  "severity": "critical|high|medium"
}}"""

    try:
        result = subprocess.run(
            ai_cli["run"] + [prompt],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout.strip()
    except Exception as e:
        return f'{{"error": "{e}"}}'


# ── 리포트 ────────────────────────────────────────────────────────────────

def print_report(total_files: int, parse_errors: int, counts: Counter,
                 samples: dict, ai_insights: dict, top_n: int):
    print("\n" + "=" * 65)
    print("  SLAyer — Vibe Coding Pattern Analysis Report")
    print(f"  파일: {total_files}개  |  파싱 오류: {parse_errors}개")
    print("=" * 65)

    print("\n📊 패턴 발생 빈도\n")
    total = total_files or 1
    for i, (pid, cnt) in enumerate(counts.most_common(top_n), 1):
        label = PATTERNS.get(pid, {}).get("label", pid)
        pct = cnt / total * 100
        bar = "█" * min(int(pct / 2), 30)
        print(f"  {i:2}. {label:<28}  {cnt:5}건  {pct:5.1f}%  {bar}")

    print("\n\n🔍 RAG 대표 예시\n")
    for pid, examples in samples.items():
        if not examples:
            continue
        label = PATTERNS.get(pid, {}).get("label", pid)
        print(f"  [{label}]")
        ex = examples[0]
        print(f"    {ex['file'].split('/')[-1]}:{ex['line']}")
        print(f"    {ex['snippet'].splitlines()[0][:80]}")
        print()

    if ai_insights:
        print("\n🤖 AI 시맨틱 분석\n")
        for pid, raw in ai_insights.items():
            label = PATTERNS.get(pid, {}).get("label", pid)
            print(f"  [{label}]")
            try:
                d = json.loads(raw)
                print(f"    왜 흔한가: {d.get('why_common','')}")
                print(f"    위험:     {d.get('risk','')}")
                print(f"    패치:     {d.get('patch_hint','')}")
            except Exception:
                print(f"    {raw[:100]}")
            print()

    top7 = [pid for pid, _ in counts.most_common(9) if pid in PATTERNS][:7]
    print("\n🎯 데이터 기반 7대 취약점 추천\n")
    for i, pid in enumerate(top7, 1):
        label = PATTERNS[pid]["label"]
        sev   = PATTERNS[pid]["severity"]
        cnt   = counts[pid]
        pct   = cnt / total * 100
        print(f"  V-{i:02d}  {pid:<28}  [{sev:<8}]  {label}  ({pct:.1f}%)")

    report = {
        "total_files": total_files,
        "parse_errors": parse_errors,
        "pattern_counts": dict(counts.most_common()),
        "top7_recommended": top7,
        "ai_insights": ai_insights,
        "rag_samples": {
            pid: [{"file": e["file"], "line": e["line"], "snippet": e["snippet"][:200]}
                  for e in exs[:3]]
            for pid, exs in samples.items()
        },
    }
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n  💾 리포트 저장: {REPORT_PATH}")


# ── 메인 ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Vibe Coding Dataset Pattern Analyzer (RAG)")
    parser.add_argument("--dataset", type=Path, default=DATASET_DIR)
    parser.add_argument("--ai",    action="store_true", help="AI CLI 시맨틱 분석 실행")
    parser.add_argument("--query", action="store_true", help="기존 인덱스로 검색만 (재인덱스 없음)")
    parser.add_argument("--top",   type=int, default=10, help="상위 N개 패턴 출력")
    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"❌ {args.dataset} 폴더가 없습니다.")
        print("   dataset/ 폴더 만들고 .py 파일을 넣어주세요.")
        return

    py_files = list(args.dataset.rglob("*.py"))
    if not py_files:
        print("❌ dataset/ 에 .py 파일이 없습니다.")
        return

    print(f"📁 {len(py_files)}개 Python 파일 발견")

    # 1. AST 분석 (전체)
    print("🔬 AST 분석 중...")
    all_hits: list[Hit] = []
    parse_errors = 0
    hit_samples: dict[str, list[Hit]] = {pid: [] for pid in PATTERNS}

    for i, f in enumerate(py_files, 1):
        if i % 100 == 0:
            print(f"  [{i}/{len(py_files)}]", end="\r")
        try:
            hits = ast_analyze(f)
            all_hits.extend(hits)
            for h in hits:
                if h.pattern_id in hit_samples and len(hit_samples[h.pattern_id]) < 10:
                    hit_samples[h.pattern_id].append(h)
        except Exception:
            parse_errors += 1

    counts = Counter(h.pattern_id for h in all_hits)
    print(f"  ✓ AST 완료: {len(all_hits)}개 hit 발견")

    # 2. ChromaDB 인덱스
    collection = None
    if not args.query:
        collection = build_index(py_files)
    elif INDEX_DIR.exists():
        try:
            import chromadb
            client = chromadb.PersistentClient(path=str(INDEX_DIR))
            collection = client.get_collection("vibe_code")
            print(f"✓ 기존 인덱스 로드: {collection.count()}개 청크")
        except Exception as e:
            print(f"⚠️  인덱스 로드 실패: {e}")

    # 3. RAG 쿼리 — 패턴별 대표 예시
    rag_samples: dict[str, list[dict]] = {}
    if collection:
        print("🔍 RAG 패턴 검색 중...")
        for pid in PATTERNS:
            if counts.get(pid, 0) > 0:
                rag_samples[pid] = rag_query(collection, pid, n_results=5)

    # AST 샘플로 폴백
    for pid in PATTERNS:
        if pid not in rag_samples or not rag_samples[pid]:
            rag_samples[pid] = [
                {"snippet": h.snippet, "file": h.file, "line": h.line}
                for h in hit_samples.get(pid, [])
            ]

    # 4. AI 시맨틱 분석
    ai_insights: dict[str, str] = {}
    if args.ai:
        ai_cli = detect_ai()
        if ai_cli:
            top_patterns = [pid for pid, _ in counts.most_common(7) if pid in PATTERNS]
            print(f"🤖 {ai_cli['name']} CLI로 {len(top_patterns)}개 패턴 분석 중...")
            for pid in top_patterns:
                examples = rag_samples.get(pid, [])
                if examples:
                    print(f"  분석 중: {pid}...")
                    ai_insights[pid] = ai_analyze_pattern(ai_cli, pid, examples)
        else:
            print("⚠️  AI CLI 없음 (claude/codex/gemini) — AI 분석 스킵")

    # 5. 리포트
    print_report(len(py_files), parse_errors, counts, rag_samples, ai_insights, args.top)


if __name__ == "__main__":
    main()
