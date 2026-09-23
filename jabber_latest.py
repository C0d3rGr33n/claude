#!/usr/bin/env python3
"""Find the latest Cisco Jabber release and print its build numbers.

Fetches with browser-like `requests` headers first; if Akamai returns an
"Access Denied" page, falls back to Playwright (chromium).
"""
import io
import os
import re
import sys
from urllib.parse import urljoin

import requests
from pypdf import PdfReader

INDEX_URL = ("https://www.cisco.com/c/en/us/support/unified-communications/"
             "jabber-android/products-release-notes-list.html")
HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"),
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "application/pdf,*/*;q=0.8"),
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.cisco.com/",
}
LINK_RE = re.compile(r'<a\b[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
TITLE_RE = re.compile(r"Cisco Jabber Release Notes?\s+for\s+(\d+\.\d+(?:\.\d+)?)\b", re.I)
PLATFORMS = ("VDI", "Windows", "Mac", "iOS", "Android")  # VDI first: its rows may mention Windows
CHROMIUM_PATHS = ("/opt/pw-browsers/chromium", "/usr/bin/chromium",
                  "/usr/bin/chromium-browser", "/usr/bin/google-chrome")
BUILD_RE = re.compile(r"\b\d+\.\d+\.\d+(?:\.\d+)?\b")


class Blocked(Exception):
    pass


def die(msg):
    sys.exit(f"ERROR: {msg}")


def is_blocked(status, body):
    head = body[:4096] if isinstance(body, bytes) else body[:4096].encode(errors="ignore")
    return status == 403 or b"Access Denied" in head


# ---------- fetchers ----------
class RequestsFetcher:
    name = "requests"

    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update(HEADERS)

    def get(self, url):
        r = self.s.get(url, timeout=30)
        if is_blocked(r.status_code, r.content):
            raise Blocked(url)
        r.raise_for_status()
        return r.content

    def close(self):
        self.s.close()


class PlaywrightFetcher:
    name = "playwright"

    def __init__(self):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(headless=True)
        except Exception:  # bundled browser missing; try a system chromium
            exe = next((c for c in CHROMIUM_PATHS if os.path.exists(c)), None)
            if not exe:
                raise
            self._browser = self._pw.chromium.launch(headless=True, executable_path=exe)
        ctx = self._browser.new_context(user_agent=HEADERS["User-Agent"],
                                        locale="en-US")
        self.page = ctx.new_page()

    def get(self, url):
        if url.lower().split("?")[0].endswith(".pdf"):
            r = self.page.request.get(url, headers={"Referer": INDEX_URL})
            status, body = r.status, r.body()
        else:
            resp = self.page.goto(url, wait_until="domcontentloaded", timeout=60000)
            status, body = (resp.status if resp else 0), self.page.content().encode()
        if is_blocked(status, body):
            raise Blocked(url)
        if status >= 400:
            raise RuntimeError(f"HTTP {status} for {url}")
        return body

    def close(self):
        self._browser.close()
        self._pw.stop()


# ---------- parsing ----------
def strip_tags(s):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s)).strip()


def vkey(v):
    return tuple(int(x) for x in v.split(".")) + (0,) * (3 - v.count(".") - 1)


def find_latest(html, base):
    """Return (version, url) of the highest-versioned release-notes link."""
    found = {}
    for href, text in LINK_RE.findall(html):
        m = TITLE_RE.search(strip_tags(text))
        if m:
            found.setdefault(m.group(1), urljoin(base, href.replace("&amp;", "&")))
    if not found:
        die("no 'Cisco Jabber Release Notes for X.Y' links found on index page")
    best = max(found, key=vkey)
    return best, found[best]


def find_pdf_link(html, base):
    hrefs = [h.replace("&amp;", "&") for h, _ in LINK_RE.findall(html)
             if h.lower().split("?")[0].endswith(".pdf")]
    return urljoin(base, hrefs[0]) if hrefs else None


def pdf_text(data):
    return "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)


def extract_builds(text):
    """Parse the 'New build numbers' section into {platform: build}."""
    m = re.search(r"New build numbers(.*?)New and updated features", text, re.S | re.I)
    if not m:
        die("'New build numbers' section not found in PDF")
    section = re.sub(r"\s+", " ", m.group(1))
    builds, prev = {}, 0
    for bm in BUILD_RE.finditer(section):
        label = section[prev:bm.start()]
        prev = bm.end()
        for plat in PLATFORMS:
            if re.search(rf"\b{plat}\b", label, re.I) and plat not in builds:
                builds[plat] = bm.group()
                break
    if not builds:
        die("build-number table not found in 'New build numbers' section")
    return builds


# ---------- main ----------
def run(fetcher):
    version, url = find_latest(fetcher.get(INDEX_URL).decode("utf-8", "replace"), INDEX_URL)
    body = fetcher.get(url)
    if not body.startswith(b"%PDF"):
        pdf_url = find_pdf_link(body.decode("utf-8", "replace"), url)
        if not pdf_url:
            die(f"no PDF link on release notes page {url}")
        url, body = pdf_url, fetcher.get(pdf_url)
    if not body.startswith(b"%PDF"):
        die(f"downloaded file is not a PDF: {url}")
    return version, url, extract_builds(pdf_text(body))


def main():
    for cls in (RequestsFetcher, PlaywrightFetcher):
        f = cls()
        try:
            version, pdf_url, builds = run(f)
            break
        except Blocked as e:
            print(f"[{f.name}] Access Denied at {e}; falling back...", file=sys.stderr)
        except (requests.RequestException, RuntimeError) as e:
            die(f"network error via {f.name}: {e}")
        finally:
            f.close()
    else:
        die("blocked by Akamai even with Playwright")

    print(f"Latest version: {version}\nPDF URL: {pdf_url}\n")
    w = max(len(p) for p in PLATFORMS)
    print(f"{'Platform':<{w + 2}}Build\n{'-' * (w + 2)}{'-' * 16}")
    for p in ("Windows", "Mac", "iOS", "Android", "VDI"):
        print(f"{p:<{w + 2}}{builds.get(p, 'n/a')}")


if __name__ == "__main__":
    main()
