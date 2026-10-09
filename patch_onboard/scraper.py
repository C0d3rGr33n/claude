"""Find Windows x64 / x86 installers starting from a product's official page."""
from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
INSTALLER_RE = re.compile(r"\.(exe|msi)(?:$|[?#])", re.I)
RAW_URL_RE = re.compile(r"https?://[^\s\"'<>()]+?\.(?:exe|msi)(?:\?[^\s\"'<>()]*)?", re.I)
FOLLOW_RE = re.compile(r"download|windows|\bwin\b|release|install|get", re.I)
DL_HINT_RE = re.compile(r"download|dl\b|/get/|installer|setup", re.I)
WIN_HINT_RE = re.compile(r"win|windows|x64|x86|msi|exe|64|32", re.I)
NON_WIN_RE = re.compile(r"(?<![a-z])(mac|macos|osx|darwin|linux|ubuntu|android|ios)(?![a-z])", re.I)
ARCH_RES = [  # order matters: "x86_64" must hit x64 before x86
    ("arm64", re.compile(r"arm64|aarch64|\barm\b", re.I)),
    ("x64", re.compile(r"x64|x86[_-]64|amd64|win64|64[-_ ]?bit|(?<![\d.])64(?![\d.])", re.I)),
    ("x86", re.compile(r"x86|win32|i[3-6]86|32[-_ ]?bit|(?<![\d.])32(?![\d.])", re.I)),
]
PENALTY_RES = [
    (re.compile(r"beta|alpha|\brc\d*\b|nightly|preview|insider|canary|dev\b", re.I), -5),
    (re.compile(r"web|online|stub|bootstrap|netinst", re.I), -3),
    (re.compile(r"debug|symbols|pdb|sdk|portable", re.I), -4),
    (re.compile(r"user[-_]?setup|per[-_]?user", re.I), -1),
    (re.compile(r"offline|full|standalone|enterprise|machine|system", re.I), 2),
    (re.compile(r"setup|install", re.I), 1),
]
PRERELEASE_RE = PENALTY_RES[0][0]
VERSION_RE = re.compile(r"(\d+(?:[._]\d+){1,3})")


@dataclass
class Candidate:
    url: str
    filename: str
    arch: str          # x64 | x86 | arm64 | unknown
    kind: str          # exe | msi
    text: str = ""
    score: int = 0
    version: tuple = ()

    def to_dict(self):
        return {k: getattr(self, k) for k in ("url", "filename", "arch", "kind", "score")} | {
            "version": ".".join(map(str, self.version))}


def classify_arch(*texts: str) -> str:
    blob = " ".join(t for t in texts if t)
    for arch, rx in ARCH_RES:
        if rx.search(blob):
            return arch
    return "unknown"


def _version(name: str) -> tuple:
    m = VERSION_RE.findall(name)
    if not m:
        return ()
    return tuple(int(x) for x in re.split(r"[._]", max(m, key=len)))


def _score(c: Candidate) -> int:
    blob = f"{c.filename} {c.text}"
    s = sum(w for rx, w in PENALTY_RES if rx.search(blob))
    return s + (1 if c.kind == "msi" else 0)  # MSI = deterministic silent install


def _site(url: str) -> str:
    return ".".join(urlparse(url).hostname.split(".")[-2:])


class InstallerScraper:
    def __init__(self, max_pages: int = 25, max_depth: int = 2, max_probes: int = 40,
                 render: bool = False, timeout: int = 30):
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        self.max_pages, self.max_depth, self.max_probes = max_pages, max_depth, max_probes
        self.render, self.timeout = render, timeout

    # ---------- page fetching ----------
    def _get_html(self, url: str) -> str:
        if self.render:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                b = p.chromium.launch()
                page = b.new_page(user_agent=UA)
                page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)
                html = page.content()
                b.close()
                return html
        r = self.s.get(url, timeout=self.timeout)
        r.raise_for_status()
        return r.text if "html" in r.headers.get("content-type", "html") else ""

    def _probe(self, url: str) -> tuple[str, str] | None:
        """Resolve an extension-less download link -> (final_url, filename)."""
        try:
            r = self.s.get(url, stream=True, allow_redirects=True, timeout=self.timeout)
            r.close()
        except requests.RequestException:
            return None
        cd = r.headers.get("content-disposition", "")
        m = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)", cd, re.I)
        name = unquote(m.group(1)) if m else unquote(urlparse(r.url).path.rsplit("/", 1)[-1])
        return (r.url, name) if INSTALLER_RE.search(name) else None

    # ---------- discovery ----------
    def _github(self, url: str) -> list[Candidate]:
        parts = urlparse(url).path.strip("/").split("/")
        if len(parts) < 2:
            return []
        api = f"https://api.github.com/repos/{parts[0]}/{parts[1]}/releases/latest"
        r = self.s.get(api, timeout=self.timeout)
        if not r.ok:
            return []
        out = []
        for a in r.json().get("assets", []):
            name = a["name"]
            if INSTALLER_RE.search(name) and not NON_WIN_RE.search(name):
                out.append(Candidate(a["browser_download_url"], name, classify_arch(name),
                                     name.rsplit(".", 1)[-1].lower()))
        return out

    def find(self, start_url: str) -> list[Candidate]:
        if urlparse(start_url).hostname in ("github.com", "www.github.com"):
            found = self._github(start_url)
            if found:
                return self._rank(found)

        site = _site(start_url)
        seen_pages, found, probes = set(), {}, 0
        queue = deque([(start_url, 0)])
        while queue and len(seen_pages) < self.max_pages:
            url, depth = queue.popleft()
            if url in seen_pages:
                continue
            seen_pages.add(url)
            try:
                html = self._get_html(url)
            except Exception as e:  # noqa: BLE001 - keep crawling
                log.debug("skip %s: %s", url, e)
                continue
            soup = BeautifulSoup(html, "html.parser")
            links = []
            for tag in soup.find_all(["a", "button", "option"]):
                href = tag.get("href") or tag.get("data-href") or tag.get("data-url") or tag.get("value")
                if not href and tag.get("onclick"):
                    m = re.search(r"['\"]((?:https?:)?/[^'\"]+)['\"]", tag["onclick"])
                    href = m.group(1) if m else None
                if href and not href.startswith(("#", "mailto:", "javascript:")):
                    links.append((urljoin(url, href), tag.get_text(" ", strip=True)[:120]))
            # URLs embedded in scripts / JSON
            links += [(u, "") for u in RAW_URL_RE.findall(html.replace("\\/", "/"))]

            for link, text in links:
                path = unquote(urlparse(link).path)
                if NON_WIN_RE.search(path) or NON_WIN_RE.search(text):
                    continue
                if INSTALLER_RE.search(path):
                    found.setdefault(link, self._cand(link, path.rsplit("/", 1)[-1], text))
                elif DL_HINT_RE.search(link + " " + text) and WIN_HINT_RE.search(link + " " + text) \
                        and probes < self.max_probes and link not in found:
                    probes += 1
                    res = self._probe(link)
                    if res:
                        found.setdefault(res[0], self._cand(res[0], res[1], text + " " + link))
                        continue
                if depth < self.max_depth and _site(link) == site and FOLLOW_RE.search(link + " " + text):
                    queue.append((link.split("#")[0], depth + 1))
        log.info("crawled %d pages, %d installer links", len(seen_pages), len(found))
        return self._rank(list(found.values()))

    @staticmethod
    def _cand(url, filename, text) -> Candidate:
        return Candidate(url, filename, classify_arch(filename, url, text),
                         filename.rsplit(".", 1)[-1].lower(), text)

    @staticmethod
    def _rank(cands: list[Candidate]) -> list[Candidate]:
        for c in cands:
            c.score, c.version = _score(c), _version(c.filename)
        return sorted(cands, key=lambda c: (c.version, c.score), reverse=True)


def pick_best(cands: list[Candidate], archs=("x64", "x86")) -> dict[str, Candidate]:
    """Best candidate per arch; 'unknown' (arch-neutral) used if an arch is missing."""
    best: dict[str, Candidate] = {}
    for arch in (*archs, "unknown"):
        pool = [c for c in cands if c.arch == arch]
        if not pool:
            continue
        stable = [c for c in pool if not PRERELEASE_RE.search(f"{c.filename} {c.text}")]
        pool = stable or pool
        top_ver = max(c.version for c in pool)
        best[arch] = max((c for c in pool if c.version == top_ver), key=lambda c: c.score)
    if any(a in best for a in archs):
        best.pop("unknown", None)
    return best
