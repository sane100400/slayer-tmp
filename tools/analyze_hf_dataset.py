"""
HuggingFace 데이터셋 기반 바이브코딩 취약 패턴 분석기

AI 생성 코드 데이터셋에서 반복적으로 나타나는 보안 취약 패턴을 통계적으로 도출.
결과가 SLAyer 7대 취약점 룰셋의 데이터 근거가 된다.

사용법:
  pip install datasets

  # MultiAIGCD — AI 생성 코드 121K (Claude/GPT/Gemini 태깅)
  python tools/analyze_hf_dataset.py --dataset s2w-ai/MultiAIGCD

  # The Stack Python 서브셋 (대규모, 스트리밍)
  python tools/analyze_hf_dataset.py --dataset bigcode/the-stack --streaming --max 50000

  # 결과 저장
  python tools/analyze_hf_dataset.py --dataset s2w-ai/MultiAIGCD --output tools/hf_pattern_report.json
"""

import ast
import re
import json
import argparse
from pathlib import Path
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterator

# ── 패턴 정의 ──────────────────────────────────────────────────────────────

PATTERNS = {
    "CWE-798_HARDCODED_SECRETS": {
        "label": "하드코딩 크레덴셜",
        "cwe": "CWE-798",
        "severity": "critical",
        "desc": "API 키·패스워드·토큰이 소스코드에 직접 할당됨",
    },
    "CWE-918_UNRESTRICTED_NETWORK": {
        "label": "무제한 외부 네트워크 호출",
        "cwe": "CWE-918",
        "severity": "critical",
        "desc": "URL 검증 없이 외부 서버로 HTTP 요청",
    },
    "CWE-94_CODE_INJECTION": {
        "label": "eval/exec 코드 인젝션",
        "cwe": "CWE-94",
        "severity": "critical",
        "desc": "사용자 입력이 eval/exec으로 동적 실행 가능",
    },
    "CWE-78_SHELL_INJECTION": {
        "label": "shell=True 명령 인젝션",
        "cwe": "CWE-78",
        "severity": "critical",
        "desc": "shell=True로 외부 명령 실행, 인젝션 위험",
    },
    "CWE-89_SQL_INJECTION": {
        "label": "SQL 인젝션",
        "cwe": "CWE-89",
        "severity": "high",
        "desc": "f-string/포맷으로 SQL 쿼리에 변수 직접 삽입",
    },
    "CWE-16_DEBUG_MODE": {
        "label": "DEBUG=True 하드코딩",
        "cwe": "CWE-16",
        "severity": "high",
        "desc": "디버그 모드가 코드에 고정되어 프로덕션 노출",
    },
    "CWE-327_WEAK_CRYPTO": {
        "label": "MD5/SHA1 약한 해시",
        "cwe": "CWE-327",
        "severity": "high",
        "desc": "패스워드 컨텍스트에서 MD5/SHA1 사용",
    },
    "CWE-390_BARE_EXCEPT": {
        "label": "빈 except 블록",
        "cwe": "CWE-390",
        "severity": "medium",
        "desc": "예외를 묵살하여 보안 이벤트 감지 불가",
    },
    "CWE-295_VERIFY_FALSE": {
        "label": "SSL 인증서 검증 비활성화",
        "cwe": "CWE-295",
        "severity": "high",
        "desc": "requests verify=False로 MITM 취약",
    },
    "CWE-330_WEAK_RANDOM": {
        "label": "암호학적으로 취약한 난수",
        "cwe": "CWE-330",
        "severity": "high",
        "desc": "보안 컨텍스트에서 random.random() 사용",
    },
}

# ── AST 탐지기 ─────────────────────────────────────────────────────────────

NETWORK_IMPORTS = {"requests", "urllib", "urllib3", "httpx", "aiohttp", "socket", "boto3"}
NETWORK_METHODS = {"get", "post", "put", "delete", "patch", "request", "urlopen"}
EXEC_CALLS      = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_output", "os.system", "os.popen",
}
SECRET_REGEXES  = [
    re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']'),
    re.compile(r'(?i)(api_key|apikey|api_secret)\s*=\s*["\'][^"\']{8,}["\']'),
    re.compile(r'(?i)(secret|token|auth_token)\s*=\s*["\'][^"\']{8,}["\']'),
    re.compile(r'sk-[A-Za-z0-9]{20,}'),
    re.compile(r'ghp_[A-Za-z0-9]{36}'),
]
SQL_RE          = re.compile(r'(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b')
DEBUG_RE        = re.compile(r'(?i)(^|\s)DEBUG\s*=\s*True')
VERIFY_FALSE_RE = re.compile(r'verify\s*=\s*False')
WEAK_RANDOM_RE  = re.compile(r'\brandom\.(random|randint|choice|shuffle)\b')
PASSWORD_VARS   = {"password", "passwd", "pwd"}


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


def _has_pwd_var(func_node) -> bool:
    return any(
        isinstance(n, ast.Name) and any(p in n.id.lower() for p in PASSWORD_VARS)
        for n in ast.walk(func_node)
    )


def _parent_func(tree, target):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(c is target for c in ast.walk(node)):
                return node
    return None


def detect_patterns(source: str) -> set[str]:
    """소스코드에서 발견된 패턴 ID 집합 반환 (파일당 중복 없이)."""
    found: set[str] = set()
    lines = source.splitlines()

    # 라인 스캔
    for line in lines:
        for rx in SECRET_REGEXES:
            if rx.search(line):
                found.add("CWE-798_HARDCODED_SECRETS")
        if DEBUG_RE.search(line):
            found.add("CWE-16_DEBUG_MODE")
        if VERIFY_FALSE_RE.search(line):
            found.add("CWE-295_VERIFY_FALSE")
        if WEAK_RANDOM_RE.search(line):
            found.add("CWE-330_WEAK_RANDOM")

    # AST 분석
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return found

    imported_net = set()

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in getattr(node, "names", []):
                mod = alias.name.split(".")[0]
                if mod in NETWORK_IMPORTS:
                    imported_net.add(mod)

        if isinstance(node, ast.Call):
            name = _call_name(node)
            ln   = getattr(node, "lineno", 0)
            snippet = lines[ln - 1].strip() if 0 < ln <= len(lines) else ""

            # NO_NETWORK
            if imported_net:
                func = node.func
                method = func.attr if isinstance(func, ast.Attribute) else None
                if method in NETWORK_METHODS:
                    found.add("CWE-918_UNRESTRICTED_NETWORK")

            # SHELL_INJECTION
            if name in EXEC_CALLS:
                found.add("CWE-78_SHELL_INJECTION")
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    found.add("CWE-78_SHELL_INJECTION")

            # CODE_INJECTION
            if name in ("eval", "exec", "compile"):
                found.add("CWE-94_CODE_INJECTION")

            # WEAK_CRYPTO
            if any(name.endswith(f) for f in ("md5", "sha1")):
                parent = _parent_func(tree, node)
                if parent and _has_pwd_var(parent):
                    found.add("CWE-327_WEAK_CRYPTO")

        # SQL_INJECTION
        if isinstance(node, ast.JoinedStr):
            ln = getattr(node, "lineno", 0)
            if 0 < ln <= len(lines) and SQL_RE.search(lines[ln - 1]):
                found.add("CWE-89_SQL_INJECTION")

        # BARE_EXCEPT
        if isinstance(node, ast.ExceptHandler):
            is_bare = node.type is None
            is_pass = (
                isinstance(getattr(node.type, "id", None), str)
                and node.type.id == "Exception"  # type: ignore
                and len(node.body) == 1
                and isinstance(node.body[0], ast.Pass)
            )
            if is_bare or is_pass:
                found.add("CWE-390_BARE_EXCEPT")

    return found


# ── HuggingFace 로더 ────────────────────────────────────────────────────────

def iter_samples(dataset_name: str, split: str, streaming: bool,
                 code_field: str, max_samples: int) -> Iterator[str]:
    """HF 데이터셋에서 Python 코드 문자열을 순회."""
    from datasets import load_dataset

    ds = load_dataset(dataset_name, split=split, streaming=streaming, trust_remote_code=True)

    count = 0
    for sample in ds:
        if count >= max_samples:
            break
        code = sample.get(code_field) or sample.get("code") or sample.get("content") or ""
        if not isinstance(code, str) or len(code) < 50:
            continue
        # Python 파일만 (언어 필드 있으면 확인)
        lang = sample.get("language") or sample.get("lang") or sample.get("programming_language") or ""
        if lang and lang.lower() not in ("python", "py", ""):
            continue
        yield code
        count += 1


def detect_code_field(dataset_name: str, split: str) -> str:
    """데이터셋의 코드 필드명 자동 탐지."""
    try:
        from datasets import load_dataset
        ds = load_dataset(dataset_name, split=split, streaming=True, trust_remote_code=True)
        sample = next(iter(ds))
        candidates = ["solution", "code", "content", "func_code_string",
                      "whole_func_string", "original_string", "text"]
        for c in candidates:
            if c in sample and isinstance(sample[c], str) and len(sample[c]) > 20:
                return c
        # fallback: 가장 긴 문자열 필드
        best = max((k for k, v in sample.items() if isinstance(v, str)), key=lambda k: len(sample[k]), default="code")
        return best
    except Exception:
        return "code"


# ── 리포트 ─────────────────────────────────────────────────────────────────

def print_report(total: int, parse_errors: int, counts: Counter,
                 llm_breakdown: dict, output_path: Path | None):
    print("\n" + "=" * 65)
    print("  SLAyer — HuggingFace Dataset Pattern Analysis")
    print(f"  분석 샘플: {total:,}개  |  파싱 오류: {parse_errors:,}개")
    print("=" * 65)

    print(f"\n📊 취약 패턴 빈도 (총 {total:,}개 샘플 기준)\n")
    for i, (pid, cnt) in enumerate(counts.most_common(), 1):
        info  = PATTERNS.get(pid, {})
        label = info.get("label", pid)
        cwe   = info.get("cwe", "")
        sev   = info.get("severity", "")
        pct   = cnt / total * 100 if total else 0
        bar   = "█" * min(int(pct / 1.5), 35)
        print(f"  {i:2}. [{cwe:<8}] {label:<28} {cnt:6,}건  {pct:5.1f}%  {bar}")

    if llm_breakdown:
        print("\n\n🤖 LLM별 패턴 빈도 비교\n")
        llms = list(llm_breakdown.keys())
        print(f"  {'패턴':<30} " + "  ".join(f"{l:<12}" for l in llms))
        print("  " + "-" * (30 + 14 * len(llms)))
        all_pids = sorted(set(pid for d in llm_breakdown.values() for pid in d), key=lambda p: -counts[p])
        for pid in all_pids[:10]:
            info = PATTERNS.get(pid, {})
            row = f"  {info.get('label', pid):<30}"
            for llm in llms:
                n     = llm_breakdown[llm].get(pid, 0)
                total_llm = sum(llm_breakdown[llm].values()) or 1
                pct   = n / total_llm * 100  # rough (per-pattern / total patterns, not per-file)
                row  += f"  {n:>5,} ({pct:4.1f}%)"
            print(row)

    # 7대 취약점 추천
    top7 = [pid for pid, _ in counts.most_common(7)]
    print(f"\n\n🎯 데이터 기반 7대 취약점 후보 ({total:,}개 샘플 관측)\n")
    for i, pid in enumerate(top7, 1):
        info  = PATTERNS[pid]
        cnt   = counts[pid]
        pct   = cnt / total * 100 if total else 0
        print(f"  V-{i:02d}  {info['cwe']:<10}  [{info['severity']:<8}]  {info['label']}")
        print(f"        {pct:.1f}% 샘플에서 발견 ({cnt:,}건)  —  {info['desc']}")
        print()

    # JSON 저장
    report = {
        "dataset_samples": total,
        "parse_errors": parse_errors,
        "pattern_counts": dict(counts.most_common()),
        "pattern_rates": {pid: round(cnt / total * 100, 2) if total else 0
                          for pid, cnt in counts.most_common()},
        "top7_recommended": top7,
        "llm_breakdown": llm_breakdown,
        "patterns_meta": {pid: PATTERNS[pid] for pid in top7},
    }

    out = output_path or Path("tools/hf_pattern_report.json")
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"  💾 리포트 저장: {out}")

    return top7


# ── 메인 ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="HuggingFace Dataset Vibe Coding Pattern Analyzer")
    parser.add_argument("--dataset",   default="code-search-net/code_search_net",
                        help="HuggingFace 데이터셋 ID (기본: code-search-net/code_search_net)")
    parser.add_argument("--split",     default="train")
    parser.add_argument("--streaming", action="store_true", default=True,
                        help="스트리밍 모드 (기본: True)")
    parser.add_argument("--max",       type=int, default=50000,
                        help="최대 분석 샘플 수 (기본: 50000)")
    parser.add_argument("--field",     default="whole_func_string",
                        help="코드 필드명 (기본: whole_func_string)")
    parser.add_argument("--output",    type=Path, default=None)
    parser.add_argument("--local",     type=Path, default=None,
                        help="로컬 .py 파일 디렉토리 분석 (HF 대신)")
    args = parser.parse_args()

    counts       = Counter()
    llm_counts   = defaultdict(Counter)
    total        = 0
    parse_errors = 0

    # ── 로컬 디렉토리 모드 ──────────────────────────────────────────────────
    if args.local:
        local_dir = Path(args.local)
        py_files  = list(local_dir.rglob("*.py"))
        print(f"📁 로컬 분석: {local_dir} ({len(py_files):,}개 .py 파일)")
        print(f"🔬 패턴 분석 중...\n")
        for fp in py_files[:args.max]:
            try:
                source = fp.read_text(encoding="utf-8", errors="ignore")
                found  = detect_patterns(source)
            except Exception:
                parse_errors += 1
                continue
            for pid in found:
                counts[pid] += 1
            total += 1
            if total % 100 == 0:
                print(f"  [{total:,}/{min(len(py_files), args.max):,}] 진행 중...")
        print(f"\n  ✓ 분석 완료: {total:,}개 파일, {sum(counts.values()):,}건 패턴 발견\n")
        print_report(total, parse_errors, counts, {}, args.output)
        return

    # ── HuggingFace 모드 ────────────────────────────────────────────────────
    print(f"📦 데이터셋 로드: {args.dataset} (split={args.split}, max={args.max:,})")
    code_field = args.field
    print(f"   코드 필드: '{code_field}'")

    try:
        from datasets import load_dataset
        ds = load_dataset(args.dataset, split=args.split, streaming=True)
    except Exception as e:
        print(f"❌ 데이터셋 로드 실패: {e}")
        print("   pip install datasets 를 먼저 실행하세요.")
        return

    print(f"🔬 패턴 분석 중...\n")

    scanned = 0
    for sample in ds:
        if total >= args.max:
            break
        if scanned % 5000 == 0 and scanned > 0:
            print(f"  [{total:,}/{args.max:,}] 진행 중... (패턴 {sum(counts.values()):,}건 발견)")
        scanned += 1

        # Python 필터
        lang = (sample.get("language") or sample.get("lang") or
                sample.get("programming_language") or "")
        if lang and lang.lower() not in ("python", "py"):
            continue

        code = (sample.get(code_field) or sample.get("whole_func_string") or
                sample.get("code") or sample.get("content") or "")
        if not isinstance(code, str) or len(code) < 30:
            continue

        try:
            found = detect_patterns(code)
        except Exception:
            parse_errors += 1
            continue

        for pid in found:
            counts[pid] += 1

        # LLM 별 집계 (태깅 데이터셋)
        llm = (sample.get("model") or sample.get("llm") or
               sample.get("generator") or sample.get("source") or "unknown")
        if llm != "unknown":
            for pid in found:
                llm_counts[str(llm)][pid] += 1

        total += 1
        if total % 1000 == 0:
            print(f"  [{total:,}/{args.max:,}] 진행 중... (패턴 {sum(counts.values()):,}건)")

    print(f"\n  ✓ 분석 완료: {total:,}개 샘플, {sum(counts.values()):,}건 패턴 발견\n")
    print_report(total, parse_errors, counts, dict(llm_counts), args.output)


if __name__ == "__main__":
    main()
