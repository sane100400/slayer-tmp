"""
Vibe Coding Dataset Collector

GitHub에서 바이브코딩 결과물(웹서비스 특화) Python 파일 수집.

사용법:
  export GITHUB_TOKEN="ghp_..."
  python tools/collect_dataset.py
  python tools/collect_dataset.py --target 5000 --output dataset/
"""

import os
import re
import time
import json
import base64
import argparse
import urllib.request
import urllib.parse
from pathlib import Path

TOKEN    = os.environ.get("GITHUB_TOKEN", "")
HEADERS  = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "slayer-dataset-collector",
}
API_BASE = "https://api.github.com"

# 바이브코딩 증거 기반 검색
# type: "code"  → /search/code API (filename: 기반)
# type: "repo"  → /search/repositories API (topic: 기반)
SEARCH_QUERIES = [
    # Claude Code 빌드 — CLAUDE.md 보유 레포 (Python)
    {"type": "code", "filename": "CLAUDE.md", "extra": "flask"},
    {"type": "code", "filename": "CLAUDE.md", "extra": "fastapi"},
    {"type": "code", "filename": "CLAUDE.md", "extra": "django"},
    {"type": "code", "filename": "CLAUDE.md", "extra": "requests"},
    # Claude Code 빌드 — CLAUDE.md 보유 레포 (JS/TS)
    {"type": "code", "filename": "CLAUDE.md", "extra": "express"},
    {"type": "code", "filename": "CLAUDE.md", "extra": "nextjs"},
    {"type": "code", "filename": "CLAUDE.md", "extra": "react"},
    # Cursor 빌드 — .cursorrules 보유 레포 (Python)
    {"type": "code", "filename": ".cursorrules", "extra": "flask"},
    {"type": "code", "filename": ".cursorrules", "extra": "fastapi"},
    # Cursor 빌드 — .cursorrules 보유 레포 (JS/TS)
    {"type": "code", "filename": ".cursorrules", "extra": "express"},
    {"type": "code", "filename": ".cursorrules", "extra": "nextjs"},
    # 명시적 토픽
    {"type": "repo", "query": "topic:vibe-coding language:python"},
    {"type": "repo", "query": "topic:vibe-coding language:javascript"},
    {"type": "repo", "query": "topic:vibe-coding language:typescript"},
    {"type": "repo", "query": "topic:built-with-claude language:python"},
    {"type": "repo", "query": "topic:built-with-claude language:javascript"},
    {"type": "repo", "query": "topic:built-with-cursor language:typescript"},
]

CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}
WEB_KEYWORDS = {
    # Python
    "flask", "fastapi", "django", "requests", "uvicorn", "starlette", "tornado",
    # JS/TS
    "express", "fastify", "next", "nuxt", "axios", "fetch", "react", "vue", "koa",
}


def api_get(url: str, params: dict = None) -> dict:
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            remaining = resp.headers.get("X-RateLimit-Remaining", "?")
            if remaining != "?" and int(remaining) < 10:
                reset = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait = max(reset - int(time.time()), 1) + 2
                print(f"\n  ⏳ Rate limit 임박 — {wait}초 대기...")
                time.sleep(wait)
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"\n  ⚠️  Rate limit 도달 — 60초 대기...")
            time.sleep(62)
            return api_get(url.split("?")[0], params)
        if e.code == 422:
            return {}
        raise


def search_repos(query: str, max_pages: int = 3) -> list[dict]:
    """레포 검색 API — topic: 쿼리에 사용."""
    repos = []
    for page in range(1, max_pages + 1):
        data = api_get(f"{API_BASE}/search/repositories", {
            "q": query, "sort": "stars", "order": "desc",
            "per_page": 30, "page": page,
        })
        items = data.get("items", [])
        if not items:
            break
        repos.extend(items)
        time.sleep(2)
    return repos


def search_repos_by_file(filename: str, extra: str = "", max_pages: int = 3) -> list[dict]:
    """코드 검색 API — filename: 기반으로 레포 목록 추출.
    CLAUDE.md / .cursorrules 보유 레포 = 바이브코딩 직접 증거.
    """
    query = f"filename:{filename}"
    if extra:
        query += f" {extra}"

    seen, repos = set(), []
    for page in range(1, max_pages + 1):
        data = api_get(f"{API_BASE}/search/code", {
            "q": query, "per_page": 30, "page": page,
        })
        items = data.get("items", [])
        if not items:
            break
        for item in items:
            repo = item.get("repository", {})
            full_name = repo.get("full_name", "")
            if full_name and full_name not in seen:
                seen.add(full_name)
                # 레포 상세 정보 가져오기
                try:
                    repo_detail = api_get(f"{API_BASE}/repos/{full_name}")
                    repos.append(repo_detail)
                    time.sleep(0.3)
                except Exception:
                    repos.append({"full_name": full_name, "stargazers_count": 0, "topics": []})
        time.sleep(2)
    return repos


def get_web_files(owner: str, repo: str, path: str = "", depth: int = 0) -> list[dict]:
    if depth > 3:
        return []
    try:
        items = api_get(f"{API_BASE}/repos/{owner}/{repo}/contents/{path}")
    except Exception:
        return []
    if not isinstance(items, list):
        return []

    files = []
    for item in items:
        ext = "." + item["name"].rsplit(".", 1)[-1] if "." in item["name"] else ""
        if item["type"] == "file" and ext in CODE_EXTENSIONS:
            files.append(item)
        elif item["type"] == "dir" and depth < 2:
            # node_modules / .git 등 제외
            if item["name"] not in {"node_modules", ".git", "__pycache__", "dist", "build", ".next"}:
                time.sleep(0.3)
                files.extend(get_web_files(owner, repo, item["path"], depth + 1))
    return files


def download_file(owner: str, repo: str, file_info: dict) -> str | None:
    try:
        data = api_get(file_info["url"])
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
    except Exception:
        pass
    return None


def is_web_service(content: str) -> bool:
    lower = content.lower()
    return any(kw in lower for kw in WEB_KEYWORDS)


def collect(target: int, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    meta_path = output_dir / "_metadata.jsonl"
    collected = 0
    seen_repos = set()

    # 이미 수집된 파일 수 확인 (py/js/ts 모두)
    existing = [f for f in output_dir.rglob("*") if f.suffix in CODE_EXTENSIONS]
    if existing:
        collected = len(existing)
        print(f"  기존 수집 파일: {collected}개")

    print(f"\n🎯 목표: {target}개 | 현재: {collected}개\n")

    for qi, q in enumerate(SEARCH_QUERIES):
        if collected >= target:
            break

        if q["type"] == "code":
            desc = f"filename:{q['filename']} + {q.get('extra','')}"
            print(f"[{qi+1}/{len(SEARCH_QUERIES)}] 코드검색: {desc}")
            repos = search_repos_by_file(q["filename"], q.get("extra", ""), max_pages=3)
        else:
            print(f"[{qi+1}/{len(SEARCH_QUERIES)}] 레포검색: {q['query'][:60]}")
            repos = search_repos(q["query"], max_pages=3)
        print(f"  레포 {len(repos)}개 발견")

        for repo in repos:
            if collected >= target:
                break

            full_name = repo["full_name"]
            if full_name in seen_repos:
                continue
            seen_repos.add(full_name)

            owner, repo_name = full_name.split("/", 1)
            print(f"  📦 {full_name} 탐색 중...", end="\r")

            web_files = get_web_files(owner, repo_name)
            time.sleep(0.5)

            saved = 0
            for f in web_files[:20]:  # 레포당 최대 20개
                if collected >= target:
                    break

                content = download_file(owner, repo_name, f)
                if not content or len(content) < 100:
                    continue
                if not is_web_service(content):
                    continue

                # 저장
                safe_name = re.sub(r'[^\w.-]', '_', f"{full_name.replace('/', '__')}__{f['path'].replace('/', '_')}")
                out_path = output_dir / safe_name
                out_path.write_text(content, encoding="utf-8")

                ext = "." + f["path"].rsplit(".", 1)[-1] if "." in f["path"] else ".py"
                with open(meta_path, "a") as mf:
                    mf.write(json.dumps({
                        "file": str(out_path.name),
                        "repo": full_name,
                        "path": f["path"],
                        "lang": ext.lstrip("."),
                        "size": f["size"],
                        "stars": repo.get("stargazers_count", 0),
                        "topics": repo.get("topics", []),
                        "source": "github",
                    }, ensure_ascii=False) + "\n")

                collected += 1
                saved += 1
                time.sleep(0.2)

            if saved:
                print(f"  ✓ {full_name}: {saved}개 저장 (총 {collected}/{target})")

    print(f"\n✅ 수집 완료: {collected}개 파일 → {output_dir}")
    print(f"   메타데이터: {meta_path}")
    return collected


def main():
    parser = argparse.ArgumentParser(description="Vibe Coding Dataset Collector")
    parser.add_argument("--target", type=int, default=3000, help="목표 파일 수")
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).parent.parent / "dataset",
                        help="저장 디렉토리")
    args = parser.parse_args()

    if not TOKEN:
        print("❌ GITHUB_TOKEN 환경변수가 없습니다.")
        print("   export GITHUB_TOKEN='ghp_...'")
        return

    print("🚀 Vibe Coding Dataset Collector")
    print(f"   목표: {args.target}개 파일")
    print(f"   저장: {args.output}")
    collect(args.target, args.output)


if __name__ == "__main__":
    main()
