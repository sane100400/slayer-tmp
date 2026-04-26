"""
Vibe Coding Web Platform Dataset Collector

바이브코딩 전용 플랫폼에서 HTML/JS/TS 코드 수집.
  - websim.com   : 사이트맵 → Playwright → HTML/JS 추출
  - CodeSandbox  : Playwright explore → REST API → 파일 추출

사용법:
  pip install playwright beautifulsoup4 lxml
  playwright install chromium

  python tools/collect_vibeweb.py
  python tools/collect_vibeweb.py --target 500 --platforms websim codesandbox
  python tools/collect_vibeweb.py --output dataset/web/ --target 1000
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.request import urlopen

try:
    from playwright.async_api import async_playwright, Page
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def _safe_name(*parts: str) -> str:
    return re.sub(r"[^\w.-]", "_", "__".join(parts))


def _write_meta(meta_path: Path, record: dict) -> None:
    with open(meta_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


# ─────────────────────────────────────────────────────────
# Platform: websim.com
# ─────────────────────────────────────────────────────────

WEBSIM_SITEMAP = "https://websim.com/sitemap.xml"
WEBSIM_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}

# websim 피드 정렬 옵션 — 각 탭에서 프로젝트 URL 추가 수집
WEBSIM_FEED_SORTS = ["hot", "new", "top", "replayed"]


def websim_urls_from_sitemap() -> list[str]:
    """사이트맵에서 고유 프로젝트 URL 수집."""
    import urllib.request as ureq
    print("📋 websim.com 사이트맵 파싱...")
    try:
        req = ureq.Request(WEBSIM_SITEMAP, headers=WEBSIM_HEADERS)
        with urlopen(req, timeout=20) as resp:
            xml_bytes = resp.read()
        root = ET.fromstring(xml_bytes)
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        seen: set[str] = set()
        urls: list[str] = []
        for loc in root.findall(".//sm:loc", ns):
            url = (loc.text or "").strip()
            if "/@" in url and url not in seen:
                seen.add(url)
                urls.append(url)
        print(f"  사이트맵: {len(urls)}개 고유 프로젝트 URL")
        return urls
    except Exception as e:
        print(f"  ❌ 사이트맵 오류: {e}")
        return []


async def websim_urls_from_feed(page, extra: int = 400) -> list[str]:
    """
    websim.com 메인 피드를 Playwright로 스크롤하며 추가 프로젝트 URL 수집.
    사이트맵 200개 + 피드 크롤 합쳐서 더 많은 URL 확보.
    """
    seen: set[str] = set()
    urls: list[str] = []

    for sort in WEBSIM_FEED_SORTS:
        if len(urls) >= extra:
            break
        feed_url = f"https://websim.com/?sort={sort}"
        try:
            await page.goto(feed_url, wait_until="domcontentloaded", timeout=20_000)
            await asyncio.sleep(2)
            # 스크롤 5회
            for _ in range(5):
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(1.5)
            html = await page.content()
            for m in re.finditer(r'href="(/@[^/"]+/[^/"]+)"', html):
                full = "https://websim.com" + m.group(1)
                if full not in seen:
                    seen.add(full)
                    urls.append(full)
        except Exception:
            pass

    print(f"  피드 크롤: {len(urls)}개 추가 URL")
    return urls


async def _capture_websim_html(page, url: str) -> str | None:
    """
    websim 프로젝트 페이지를 로드하면서 *.c.websim.com 응답을 캡처해
    AI 생성 HTML 소스를 반환한다.

    page.expect_response() 를 사용해 async body() 를 올바르게 await 한다.
    타임아웃 10초 — 시뮬레이션 iframe 없는 페이지는 빠르게 skip.
    """
    try:
        async with page.expect_response(
            lambda r: "c.websim.com" in r.url,
            timeout=10_000,
        ) as resp_info:
            await page.goto(url, wait_until="domcontentloaded", timeout=15_000)

        response = await resp_info.value
        body = await response.body()
        if len(body) > 300:
            return body.decode("utf-8", errors="ignore")
    except Exception:
        pass
    return None


async def collect_websim(
    target: int,
    output_dir: Path,
    meta_path: Path,
) -> int:
    if not HAS_PLAYWRIGHT:
        print("  ❌ playwright 없음: pip install playwright && playwright install chromium")
        return 0

    collected = 0

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context(
            user_agent=WEBSIM_HEADERS["User-Agent"],
            viewport={"width": 1280, "height": 800},
        )
        page = await ctx.new_page()

        # 1단계: 사이트맵 URL
        sitemap_urls = websim_urls_from_sitemap()
        # 2단계: 피드 크롤 (사이트맵이 부족할 때 보완)
        feed_urls = await websim_urls_from_feed(page, extra=max(target * 3, 600))
        # 합치기 (사이트맵 우선, 중복 제거)
        seen: set[str] = set(sitemap_urls)
        all_urls = list(sitemap_urls)
        for u in feed_urls:
            if u not in seen:
                seen.add(u)
                all_urls.append(u)
        print(f"  총 {len(all_urls)}개 URL 대상")

        for url in all_urls:
            if collected >= target:
                break

            m = re.search(r"/@([^/]+)/([^/?#]+)", url)
            if not m:
                continue
            user, proj = m.group(1), m.group(2)
            label = f"{user}/{proj}"

            # 이미 저장된 파일 skip
            fname = _safe_name("websim", user, proj) + ".html"
            if (output_dir / fname).exists():
                continue

            html = await _capture_websim_html(page, url)

            if not html or len(html) < 300:
                continue

            (output_dir / fname).write_text(html, encoding="utf-8")
            _write_meta(meta_path, {
                "file": fname,
                "url": url,
                "platform": "websim",
                "user": user,
                "project": proj,
                "size": len(html),
            })
            collected += 1
            print(f"  ✓ [{collected}/{target}] {label}  ({len(html):,} bytes)")
            await asyncio.sleep(0.8)

        await browser.close()

    return collected


# ─────────────────────────────────────────────────────────
# Platform: CodeSandbox
# ─────────────────────────────────────────────────────────

CSB_API = "https://codesandbox.io/api/v1/sandboxes"
CSB_EXPLORE = "https://codesandbox.io/explore"

# 웹서비스 관련 템플릿
CSB_TEMPLATES = [
    "react-ts",
    "react",
    "nextjs",
    "vue",
    "svelte",
    "node",
    "vanilla-ts",
    "vanilla",
]

ALGOLIA_APP_ID   = "WKDM4EIRFF"   # CodeSandbox 공개 Algolia 앱 (코드 탐색에서 발견)
ALGOLIA_API_KEY  = "a5d1ae97f5ea4f89ad2ce9b2e9fbffca"


def _csb_algolia_search(query: str, page: int = 0, hits: int = 50) -> list[str]:
    """
    CodeSandbox 가 사용하는 Algolia 인덱스로 sandbox ID 수집.
    공개 API 키이므로 검색 전용(읽기 전용) 접근만 가능.
    """
    import urllib.request, urllib.parse
    url = (
        f"https://{ALGOLIA_APP_ID.lower()}-dsn.algolia.net"
        f"/1/indexes/sandboxes/query"
    )
    payload = json.dumps({
        "query": query,
        "page": page,
        "hitsPerPage": hits,
        "attributesToRetrieve": ["objectID", "title", "template"],
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "X-Algolia-Application-Id": ALGOLIA_APP_ID,
            "X-Algolia-API-Key": ALGOLIA_API_KEY,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        return [hit["objectID"] for hit in data.get("hits", [])]
    except Exception:
        return []


async def _csb_playwright_ids(max_ids: int = 300) -> list[str]:
    """Playwright 으로 CodeSandbox explore 페이지에서 ID 수집."""
    ids: set[str] = set()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            await page.goto(CSB_EXPLORE, wait_until="networkidle", timeout=40_000)
            for _ in range(6):
                await page.keyboard.press("End")
                await asyncio.sleep(1.5)
            html = await page.content()
            for m in re.finditer(r'/s/([a-z0-9][a-z0-9-]{3,})', html):
                ids.add(m.group(1))
                if len(ids) >= max_ids:
                    break
        except Exception as e:
            print(f"  ⚠️  CodeSandbox Playwright 오류: {e}")
        finally:
            await browser.close()
    return list(ids)


def _csb_fetch(sandbox_id: str) -> dict | None:
    import urllib.request
    try:
        req = urllib.request.Request(
            f"{CSB_API}/{sandbox_id}",
            headers={"User-Agent": "slayer-dataset/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        sb = data.get("data", {})
        modules = sb.get("modules", [])
        files = {
            mod["title"]: mod["code"]
            for mod in modules
            if mod.get("title") and mod.get("code") and len(mod["code"]) > 10
        }
        if not files:
            return None

        return {
            "sandbox_id": sandbox_id,
            "title": sb.get("title", ""),
            "description": sb.get("description", ""),
            "template": sb.get("template", ""),
            "files": files,
        }
    except Exception:
        return None


async def collect_codesandbox(
    target: int,
    output_dir: Path,
    meta_path: Path,
) -> int:
    print("📋 CodeSandbox sandbox ID 수집 중...")

    ids: list[str] = []

    # 1차: Algolia 검색 (vibe coding 관련 쿼리)
    algolia_queries = [
        "vibe coding",
        "ai generated",
        "cursor ai",
        "claude ai",
        "chatgpt",
        "web app dashboard",
        "react fastapi",
        "fullstack nextjs",
    ]
    for q in algolia_queries:
        for pg in range(3):
            chunk = _csb_algolia_search(q, page=pg)
            ids.extend(chunk)
            if not chunk:
                break
            time.sleep(0.3)

    # 2차: Playwright explore (Algolia 실패 시 보완)
    if len(ids) < 50 and HAS_PLAYWRIGHT:
        print("  Playwright explore 보완 수집...")
        ids.extend(await _csb_playwright_ids(max_ids=target * 3))

    ids = list(dict.fromkeys(ids))  # deduplicate, preserve order
    print(f"  {len(ids)}개 sandbox ID 확보 → API 수집 시작...")

    collected = 0
    for sb_id in ids:
        if collected >= target:
            break

        data = _csb_fetch(sb_id)
        if not data:
            time.sleep(0.3)
            continue

        fname = _safe_name("csb", sb_id) + ".json"
        (output_dir / fname).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        _write_meta(meta_path, {
            "file": fname,
            "sandbox_id": sb_id,
            "platform": "codesandbox",
            "title": data["title"],
            "template": data["template"],
            "file_count": len(data["files"]),
        })
        collected += 1
        if collected % 20 == 0:
            print(f"  ✓ [{collected}/{target}] CodeSandbox 수집 중...")
        time.sleep(0.4)

    print(f"  ✓ CodeSandbox: {collected}개 수집 완료")
    return collected


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

PLATFORM_COLLECTORS = {
    "websim": collect_websim,
    "codesandbox": collect_codesandbox,
}


async def _run(args: argparse.Namespace) -> None:
    out: Path = args.output
    out.mkdir(parents=True, exist_ok=True)
    meta = out / "_metadata_web.jsonl"

    total = 0
    per = args.target // len(args.platforms)

    for platform in args.platforms:
        remaining = args.target - total
        if remaining <= 0:
            break
        quota = min(per, remaining)

        print(f"\n{'='*54}")
        print(f"🎯  Platform: {platform}  (목표 {quota}개)")
        print("=" * 54)

        collector = PLATFORM_COLLECTORS[platform]
        n = await collector(quota, out, meta)
        total += n
        print(f"  → {platform} 완료: {n}개")

    print(f"\n{'='*54}")
    print(f"✅  전체 수집 완료: {total}개  →  {out}")
    print(f"   메타데이터: {meta}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="바이브코딩 웹 플랫폼 데이터셋 수집기",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target",    type=int,  default=500,
                        help="수집 목표 파일 수 (기본 500)")
    parser.add_argument("--output",    type=Path,
                        default=Path(__file__).resolve().parent.parent / "dataset" / "web",
                        help="저장 디렉토리")
    parser.add_argument("--platforms", nargs="+",
                        default=["websim", "codesandbox"],
                        choices=list(PLATFORM_COLLECTORS),
                        help="수집 플랫폼 (기본: websim codesandbox)")
    args = parser.parse_args()

    if not HAS_PLAYWRIGHT:
        print("❌  Playwright 가 필요합니다:")
        print("     pip install playwright")
        print("     playwright install chromium")
        return

    print("🚀  Vibe Coding Web Platform Collector")
    print(f"    목표  : {args.target}개")
    print(f"    저장  : {args.output}")
    print(f"    플랫폼: {', '.join(args.platforms)}")
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
