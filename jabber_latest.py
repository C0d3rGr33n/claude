#!/usr/bin/env python3
"""Find the latest Cisco Jabber release and print its build numbers.

Fetches with browser-like `requests` headers first; if Akamai returns an
"Access Denied" page, falls back to Playwright (chromium).
"""
import argparse
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
            raise Blocked(url, r.content)
        r.raise_for_status()
        return r.content

    def close(self):
        self.s.close()


class PlaywrightFetcher:
    """Chromium via Playwright; tweaked to look less like automation to Akamai."""
    STEALTH_JS = ("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
                  "window.chrome = window.chrome || {runtime: {}};")

    def __init__(self, headless=True):
        from playwright.sync_api import sync_playwright
        self.name = "playwright" + ("" if headless else " (headed)")
        self._pw = sync_playwright().start()
        opts = dict(headless=headless, args=["--disable-blink-features=AutomationControlled"])
        self._browser = None
        # Prefer real Chrome (best fingerprint), then bundled, then a system chromium.
        attempts = [dict(channel="chrome"), {}] + [dict(executable_path=c)
                                                    for c in CHROMIUM_PATHS if os.path.exists(c)]
        for extra in attempts:
            try:
                self._browser = self._pw.chromium.launch(**opts, **extra)
                break
            except Exception as e:
                err = e
        if not self._browser:
            self._pw.stop()
            raise RuntimeError(f"could not launch chromium: {err}")
        ctx = self._browser.new_context(locale="en-US", viewport={"width": 1366, "height": 900},
                                        extra_http_headers={"Accept-Language": HEADERS["Accept-Language"]})
        ctx.add_init_script(self.STEALTH_JS)
        self.page = ctx.new_page()
        self._warmed = False

    def _warm_up(self, url):
        # Visit the site root first so Akamai's sensor script can set its cookies.
        if not self._warmed and "cisco.com" in url:
            self._warmed = True
            try:
                self.page.goto("https://www.cisco.com/", wait_until="load", timeout=60000)
                self.page.wait_for_timeout(3000)
            except Exception:
                pass

    def get(self, url):
        self._warm_up(url)
        if url.lower().split("?")[0].endswith(".pdf"):
            r = self.page.request.get(url, headers={"Referer": self.page.url or INDEX_URL})
            status, body = r.status, r.body()
        else:
            resp = self.page.goto(url, wait_until="domcontentloaded", timeout=60000)
            self.page.wait_for_timeout(1500)
            status, body = (resp.status if resp else 0), self.page.content().encode()
        if is_blocked(status, body):
            raise Blocked(url, body)
        if status >= 400:
            raise RuntimeError(f"HTTP {status} for {url}")
        return body

    def close(self):
        self._browser.close()
        self._pw.stop()


def has_display():
    return sys.platform in ("win32", "darwin") or bool(os.environ.get("DISPLAY")
                                                        or os.environ.get("WAYLAND_DISPLAY"))


# ---------- parsing ----------
def strip_tags(s):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s)).strip()


def vkey(v):
    return tuple(int(x) for x in v.split(".")) + (0,) * (3 - v.count(".") - 1)


def find_releases(html, base):
    """Return {version: url} for every 'Cisco Jabber Release Notes for X.Y' link."""
    found = {}
    for href, text in LINK_RE.findall(html):
        m = TITLE_RE.search(strip_tags(text))
        if m:
            found.setdefault(m.group(1), urljoin(base, href.replace("&amp;", "&")))
    if not found:
        die("no 'Cisco Jabber Release Notes for X.Y' links found on index page")
    return found


def matches(version, prefix):
    """True if version starts with prefix component-wise ('15' ~ 15.x, '15.2' ~ 15.2.x)."""
    return not prefix or version.split(".")[:len(prefix.split("."))] == prefix.split(".")


def find_latest(found, prefix=None):
    """Return (version, url) of the highest version matching prefix."""
    pool = [v for v in found if matches(v, prefix)]
    if not pool:
        die(f"no release matching '{prefix}'. Available: "
            + ", ".join(sorted(found, key=vkey, reverse=True)))
    best = max(pool, key=vkey)
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
def run(fetcher, prefix=None, list_only=False):
    found = find_releases(fetcher.get(INDEX_URL).decode("utf-8", "replace"), INDEX_URL)
    if list_only:
        return found
    version, url = find_latest(found, prefix)
    body = fetcher.get(url)
    if not body.startswith(b"%PDF"):
        pdf_url = find_pdf_link(body.decode("utf-8", "replace"), url)
        if not pdf_url:
            die(f"no PDF link on release notes page {url}")
        url, body = pdf_url, fetcher.get(pdf_url)
    if not body.startswith(b"%PDF"):
        die(f"downloaded file is not a PDF: {url}")
    return version, url, extract_builds(pdf_text(body))


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version", nargs="?",
                    help="only consider this major/minor line, e.g. 14 or 15.2 (default: all)")
    ap.add_argument("--list", action="store_true", help="list all versions found and exit")
    a = ap.parse_args()
    if a.version and not re.fullmatch(r"\d+(\.\d+){0,2}", a.version):
        ap.error("version must look like 15, 15.2 or 15.2.1")
    return a


def main():
    args = parse_args()
    fetchers = [RequestsFetcher, PlaywrightFetcher]
    if has_display():
        fetchers.append(lambda: PlaywrightFetcher(headless=False))
    last = None
    for make in fetchers:
        try:
            f = make()
        except RuntimeError as e:
            print(f"[skip] {e}", file=sys.stderr)
            continue
        try:
            result = run(f, args.version, args.list)
            break
        except Blocked as e:
            last = e
            print(f"[{f.name}] Access Denied at {e.args[0]}; falling back...", file=sys.stderr)
        except (requests.RequestException, RuntimeError) as e:
            die(f"network error via {f.name}: {e}")
        finally:
            f.close()
    else:
        snippet = last.args[1][:400].decode("utf-8", "replace") if last else ""
        die("blocked by Akamai with every method.\n"
            "Akamai often blocks by IP reputation (VPN, cloud or datacenter IPs); "
            "try from a home/office network, or with a visible browser (needs a display).\n"
            f"Page start:\n{snippet}")

    if args.list:
        for v in sorted(result, key=vkey, reverse=True):
            print(f"{v:<10}{result[v]}")
        return
    version, pdf_url, builds = result
    label = f"Latest {args.version}.x version" if args.version else "Latest version"
    print(f"{label}: {version}\nPDF URL: {pdf_url}\n")
    w = max(len(p) for p in PLATFORMS)
    print(f"{'Platform':<{w + 2}}Build\n{'-' * (w + 2)}{'-' * 16}")
    for p in ("Windows", "Mac", "iOS", "Android", "VDI"):
        print(f"{p:<{w + 2}}{builds.get(p, 'n/a')}")


if __name__ == "__main__":
    main()
