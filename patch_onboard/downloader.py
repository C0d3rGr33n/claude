"""Download an installer and inspect it (type, packaging framework, arch)."""
from __future__ import annotations

import hashlib
import logging
import re
import struct
import time
import zipfile
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests

from .scraper import UA

log = logging.getLogger(__name__)

PE_MACHINE = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64"}
# byte signature -> framework (first match wins)
FRAMEWORK_SIGS = [
    (b".wixburn", "wixburn"),
    (b"Inno Setup Setup Data", "inno"),
    (b"Nullsoft", "nsis"),
    (b"Advanced Installer", "advinst"),
    (b"InstallShield", "installshield"),
    (b"InstallAware", "installaware"),
    (b"SquirrelSetup", "squirrel"),
    (b"Squirrel", "squirrel"),
    (b"Wise Installation", "wise"),
    (b"7zS.sfx", "7zsfx"),
    (b"Setup Factory", "setupfactory"),
]


def download(url: str, dest: Path, retries: int = 4) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    s = requests.Session()
    s.headers["User-Agent"] = UA
    for attempt in range(retries):
        try:
            with s.get(url, stream=True, timeout=60, allow_redirects=True) as r:
                r.raise_for_status()
                m = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)",
                              r.headers.get("content-disposition", ""), re.I)
                name = unquote(m.group(1) if m else urlparse(r.url).path.rsplit("/", 1)[-1]) or "setup.exe"
                path = dest / re.sub(r"[^\w.\-]", "_", name)
                with open(path, "wb") as fh:
                    for chunk in r.iter_content(1 << 20):
                        fh.write(chunk)
            ftype = sniff(path)
            if ftype == "zip":
                return _from_zip(path, dest)
            if ftype not in ("exe", "msi"):
                raise ValueError(f"{name} is not an installer (got {ftype})")
            return path
        except (requests.RequestException, OSError) as e:
            wait = 2 ** (attempt + 1)
            log.warning("download failed (%s), retry in %ss", e, wait)
            time.sleep(wait)
    raise RuntimeError(f"download failed: {url}")


def sniff(path: Path) -> str:
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head[:2] == b"MZ":
        return "exe"
    if head == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        return "msi"
    if head[:2] == b"PK":
        return "zip"
    return "html" if head.lstrip()[:1] == b"<" else "unknown"


def _from_zip(path: Path, dest: Path) -> Path:
    out = dest / (path.stem + "_unzipped")
    with zipfile.ZipFile(path) as z:
        z.extractall(out)
    found = [p for p in out.rglob("*") if p.suffix.lower() in (".msi", ".exe")]
    if not found:
        raise ValueError("zip contains no .exe/.msi")
    found.sort(key=lambda p: (p.suffix.lower() != ".msi", "setup" not in p.name.lower(), -p.stat().st_size))
    return found[0]


def pe_arch(path: Path) -> str:
    with open(path, "rb") as fh:
        fh.seek(0x3C)
        off = struct.unpack("<I", fh.read(4))[0]
        fh.seek(off)
        if fh.read(4) != b"PE\0\0":
            return "unknown"
        return PE_MACHINE.get(struct.unpack("<H", fh.read(2))[0], "unknown")


def detect_framework(path: Path, chunk: int = 32 << 20) -> str:
    size = path.stat().st_size
    with open(path, "rb") as fh:
        data = fh.read(chunk)
        if size > chunk:
            fh.seek(max(chunk, size - chunk))
            data += fh.read()
    for sig, name in FRAMEWORK_SIGS:
        if sig in data:
            return name
    return "unknown"


def msi_info(path: Path) -> dict:
    import olefile
    with olefile.OleFileIO(str(path)) as ole:
        md = ole.get_metadata()
    dec = lambda v: v.decode("utf-8", "replace") if isinstance(v, bytes) else v  # noqa: E731
    template = dec(md.template) or ""
    plat = template.split(";")[0].lower()
    arch = {"x64": "x64", "intel64": "x64", "amd64": "x64", "intel": "x86", "arm64": "arm64"}.get(plat, "unknown")
    return {"template": template, "arch": arch, "title": dec(md.title), "subject": dec(md.subject),
            "author": dec(md.author), "package_code": dec(md.revision_number)}


def inspect(path: Path, hinted_arch: str = "unknown") -> dict:
    kind = sniff(path)
    info = {"path": str(path), "filename": path.name, "kind": kind, "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    if kind == "msi":
        info["framework"] = "msi"
        info["msi"] = msi_info(path)
        arch = info["msi"]["arch"]
    else:
        info["framework"] = detect_framework(path)
        info["pe_arch"] = pe_arch(path)
        # Many x64 installers ship a 32-bit bootstrapper, so PE arch only counts as x64 evidence.
        arch = "x64" if info["pe_arch"] == "x64" else "unknown"
    info["arch"] = hinted_arch if hinted_arch in ("x64", "x86", "arm64") else (arch if arch != "unknown" else "neutral")
    return info
