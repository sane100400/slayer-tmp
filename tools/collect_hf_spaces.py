"""
HuggingFace Spaces 바이브코딩 웹서비스 수집기

Gradio/Streamlit Space = AI 도구로 빌드된 직접 증거.
각 Space의 .py / .js / .ts / .jsx / .tsx 파일을 다운로드해 dataset/ 폴더에 저장.

웹서비스 특화: Python + JS/TS 모두 수집.

사용법:
  python tools/collect_hf_spaces.py
  python tools/collect_hf_spaces.py --target 2000 --output dataset/
"""

import json
import re
import time
import argparse
import urllib.request
import urllib.parse
from pathlib import Path

HF_API = "https://huggingface.co/api"
HF_RAW = "https://huggingface.co/spaces/{space_id}/raw/main/{path}"

WEB_KEYWORDS_PY = {
    "gradio", "streamlit", "flask", "fastapi", "django",
    "requests", "uvicorn", "starlette", "tornado", "aiohttp",
}
WEB_KEYWORDS_JS = {
    "express", "fastify", "next", "nuxt", "axios", "fetch",
    "react", "vue", "angular", "koa", "hapi", "nestjs",
}
CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx"}

HEADERS = {"User-Agent": "slayer-dataset-collector/1.0"}


def api_get(url: str, params: dict = None) -> dict:
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print("  ⏳ Rate limit — 30초 대기...")
            time.sleep(30)
            return api_get(url.split("?")[0], params)
        if e.code in (403, 404):
            return {}
        raise
    except Exception:
        return {}


def download_raw(space_id: str, path: str) -> str | None:
    url = HF_RAW.format(space_id=space_id, path=urllib.parse.quote(path))
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def list_spaces_page(sdk: str, limit: int = 100, offset: int = 0) -> list[dict]:
    """HF API로 Spaces 목록 (페이지 단위)."""
    data = api_get(f"{HF_API}/spaces", {
        "filter": sdk,
        "sort": "likes",
        "limit": limit,
        "offset": offset,
        "full": "true",
    })
    if isinstance(data, list):
        return data
    return []


def get_web_files(space_id: str) -> list[str]:
    """Space 내 웹서비스 코드 파일 목록 반환 (.py/.js/.ts/.jsx/.tsx)."""
    data = api_get(f"{HF_API}/spaces/{space_id}")
    siblings = data.get("siblings", [])
    return [f["rfilename"] for f in siblings
            if isinstance(f, dict)
            and any(f.get("rfilename", "").endswith(ext) for ext in CODE_EXTENSIONS)]


def is_web_service(content: str, ext: str = ".py") -> bool:
    lower = content.lower()
    if ext in (".js", ".ts", ".jsx", ".tsx"):
        return any(kw in lower for kw in WEB_KEYWORDS_JS | WEB_KEYWORDS_PY)
    return any(kw in lower for kw in WEB_KEYWORDS_PY)


def collect(target: int, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    meta_path = output_dir / "_metadata_spaces.jsonl"

    # 기존 파일 수 파악 (spaces 수집분 포함 전체 기준)
    existing = list(output_dir.rglob("*.py"))
    collected = len(existing)
    seen_spaces = set()
    print(f"  기존 수집 파일: {collected}개")
    print(f"\n🎯 목표: {target}개 | 현재: {collected}개\n")

    sdks = ["gradio", "streamlit"]
    offset = 0
    batch = 100

    while collected < target:
        for sdk in sdks:
            if collected >= target:
                break

            print(f"[SDK: {sdk}] offset={offset} 조회 중...")
            spaces = list_spaces_page(sdk, limit=batch, offset=offset)
            if not spaces:
                print(f"  더 이상 {sdk} space 없음.")
                continue

            print(f"  {len(spaces)}개 발견")

            for space in spaces:
                if collected >= target:
                    break

                space_id = space.get("id", "")
                if not space_id or space_id in seen_spaces:
                    continue
                seen_spaces.add(space_id)

                print(f"  📦 {space_id} ...", end="\r")
                web_files = get_web_files(space_id)
                time.sleep(0.3)

                saved = 0
                for path in web_files[:20]:  # space당 최대 20개
                    if collected >= target:
                        break

                    ext = Path(path).suffix.lower()
                    content = download_raw(space_id, path)
                    if not content or len(content) < 100:
                        continue
                    if not is_web_service(content, ext):
                        continue

                    safe_name = re.sub(
                        r'[^\w.-]', '_',
                        f"hf__{space_id.replace('/', '__')}__{path.replace('/', '_')}"
                    )
                    out_path = output_dir / safe_name
                    out_path.write_text(content, encoding="utf-8")

                    with open(meta_path, "a") as mf:
                        mf.write(json.dumps({
                            "file": out_path.name,
                            "space": space_id,
                            "path": path,
                            "lang": ext.lstrip("."),
                            "size": len(content),
                            "sdk": sdk,
                            "likes": space.get("likes", 0),
                            "source": "hf_spaces",
                        }, ensure_ascii=False) + "\n")

                    collected += 1
                    saved += 1
                    time.sleep(0.1)

                if saved:
                    print(f"  ✓ {space_id}: {saved}개 저장 (총 {collected}/{target})")

        offset += batch
        if offset > 3000:
            print("offset 한계 도달. 종료.")
            break

    print(f"\n✅ 수집 완료: {collected}개 파일 → {output_dir}")
    return collected


def main():
    parser = argparse.ArgumentParser(description="HuggingFace Spaces Python Collector")
    parser.add_argument("--target", type=int, default=2000)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).parent.parent / "dataset")
    args = parser.parse_args()

    print("🚀 HuggingFace Spaces Collector")
    print(f"   목표: {args.target}개 파일 (Gradio + Streamlit)")
    print(f"   저장: {args.output}")
    collect(args.target, args.output)


if __name__ == "__main__":
    main()
