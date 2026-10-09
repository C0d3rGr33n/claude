"""Registry + C:\\ snapshots taken inside the guest and parsed on the host."""
from __future__ import annotations

import json
import logging
import re
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .vm import Guest, ps_quote

log = logging.getLogger(__name__)

REG_ROOTS = {
    "hklm_software": r"HKLM\SOFTWARE",
    "hklm_services": r"HKLM\SYSTEM\CurrentControlSet\Services",
    "hklm_session": r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
    "hkcu_software": r"HKCU\Software",
    "hku_default": r"HKU\.DEFAULT\Software",
}
PE_EXT = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".drv", ".scr", ".msi", ".node", ".pyd", ".ax", ".mui"}

# Guest-side: iterative walk, skips reparse points (junction loops), tolerates ACL errors.
FILES_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$excl = @(__EXCL__) | % { $_.TrimEnd('\').ToLower() }
$w = New-Object IO.StreamWriter(__OUT__, $false, (New-Object Text.UTF8Encoding $false))
$stack = New-Object Collections.Stack
$stack.Push('C:\')
while ($stack.Count) {
  $d = $stack.Pop()
  try {
    foreach ($e in (New-Object IO.DirectoryInfo($d)).GetFileSystemInfos()) {
      if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
      if ($e -is [IO.DirectoryInfo]) {
        if ($excl -notcontains $e.FullName.ToLower()) { $stack.Push($e.FullName) }
      } else { $w.WriteLine($e.FullName + "`t" + $e.Length + "`t" + $e.LastWriteTimeUtc.Ticks) }
    }
  } catch {}
}
$w.Close()
"""

DETAILS_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$pe = @(__PEEXT__)
$r = foreach ($p in [IO.File]::ReadAllLines(__LIST__)) {
  $o = [ordered]@{ path = $p; sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
  if ($pe -contains [IO.Path]::GetExtension($p).ToLower()) {
    $i = [Diagnostics.FileVersionInfo]::GetVersionInfo($p)
    $o.file_version = "$($i.FileMajorPart).$($i.FileMinorPart).$($i.FileBuildPart).$($i.FilePrivatePart)"
    $o.file_version_str = $i.FileVersion; $o.product_version = $i.ProductVersion
    $o.product_name = $i.ProductName; $o.company = $i.CompanyName; $o.description = $i.FileDescription
    $sig = Get-AuthenticodeSignature -LiteralPath $p
    $o.signature = "$($sig.Status)"; $o.signer = $sig.SignerCertificate.Subject
  }
  [pscustomobject]$o
}
[IO.File]::WriteAllText(__OUT__, (ConvertTo-Json -Depth 3 -InputObject @($r)))
"""


@dataclass
class Snapshot:
    # key_lower -> (Key, {name_lower: (Name, raw_value)})
    registry: dict = field(default_factory=dict)
    # path_lower -> (Path, size, mtime_ticks)
    files: dict = field(default_factory=dict)


# ---------------- .reg parsing ----------------
VALUE_RE = re.compile(r'^(@|"(?:[^"\\]|\\.)*")=(.*)$', re.S)


def _unescape(s: str) -> str:
    return re.sub(r'\\(.)', r'\1', s)


def parse_reg(text: str, into: dict | None = None) -> dict:
    keys = {} if into is None else into
    cur = None
    buf = ""
    for line in text.splitlines():
        if buf:
            line = buf + line.lstrip()
            buf = ""
        if line.endswith("\\") and not line.startswith("["):
            buf = line[:-1]
            continue
        if line.startswith("[") and line.endswith("]"):
            k = line[1:-1]
            cur = keys.setdefault(k.lower(), (k, {}))[1]
        elif cur is not None and line:
            m = VALUE_RE.match(line)
            if m:
                name = "" if m.group(1) == "@" else _unescape(m.group(1)[1:-1])
                cur[name.lower()] = (name or "(Default)", m.group(2))
    return keys


def decode_value(raw: str):
    """Human readable form of a .reg value literal."""
    if raw.startswith('"'):
        return _unescape(raw[1:-1])
    if raw.startswith("dword:"):
        return int(raw[6:], 16)
    m = re.match(r"hex(?:\((\w+)\))?:(.*)", raw, re.S)
    if not m:
        return raw
    kind, data = m.group(1), bytes(int(b, 16) for b in re.findall(r"[0-9a-fA-F]{2}", m.group(2)))
    if kind == "b":
        return int.from_bytes(data, "little")
    if kind in ("2", "7"):
        s = data.decode("utf-16-le", "replace").rstrip("\0")
        return s.split("\0") if kind == "7" else s
    return data.hex()


def parse_files(text: str, into: dict | None = None) -> dict:
    files = {} if into is None else into
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            files[parts[0].lower()] = (parts[0], int(parts[1]), int(parts[2]))
    return files


# ---------------- guest orchestration ----------------
def take_snapshot(guest: Guest, work_dir: str, excludes: list[str], label: str, keep_dir: Path | None = None) -> Snapshot:
    d = f"{work_dir}\\snap_{label}"
    log.info("%s: snapshot '%s' (registry + C:\\)", guest.vm.name, label)
    exports = "; ".join(f"reg export {ps_quote(root)} {ps_quote(d + chr(92) + name + '.reg')} /y | Out-Null"
                        for name, root in REG_ROOTS.items())
    excl = ", ".join(ps_quote(x) for x in [*excludes, work_dir, r"C:\pagefile.sys"])
    guest.ps(f"New-Item -ItemType Directory -Force {ps_quote(d)} | Out-Null; {exports}", check=False)
    guest.ps(FILES_PS.replace("__EXCL__", excl).replace("__OUT__", ps_quote(d + r"\files.tsv")), check=False)
    zip_remote = f"{work_dir}\\snap_{label}.zip"
    guest.ps(f"Compress-Archive -Path {ps_quote(d + chr(92) + '*')} -DestinationPath {ps_quote(zip_remote)} -Force")

    tmp = keep_dir or Path(tempfile.mkdtemp(prefix="snap_"))
    local_zip = tmp / f"{guest.vm.name}_{label}.zip"
    guest.fetch(zip_remote, str(local_zip))
    snap = Snapshot()
    with zipfile.ZipFile(local_zip) as z:
        for n in z.namelist():
            raw = z.read(n)
            if n.endswith(".reg"):
                parse_reg(raw.decode("utf-16"), snap.registry)
            elif n.endswith("files.tsv"):
                parse_files(raw.decode("utf-8", "replace"), snap.files)
    log.info("snapshot '%s': %d keys, %d files", label, len(snap.registry), len(snap.files))
    return snap


def file_details(guest: Guest, work_dir: str, paths: list[str]) -> dict[str, dict]:
    """Version / hash / signature for the given guest paths."""
    if not paths:
        return {}
    with tempfile.TemporaryDirectory() as t:
        lst = Path(t) / "paths.txt"
        lst.write_text("\r\n".join(paths), encoding="utf-8")
        guest.copy_to(str(lst), f"{work_dir}\\paths.txt")
        out_remote = f"{work_dir}\\details.json"
        guest.ps(DETAILS_PS.replace("__PEEXT__", ", ".join(ps_quote(e) for e in sorted(PE_EXT)))
                 .replace("__LIST__", ps_quote(f"{work_dir}\\paths.txt")).replace("__OUT__", ps_quote(out_remote)),
                 check=False)
        local = Path(t) / "details.json"
        guest.fetch(out_remote, str(local))
        data = json.loads(local.read_text(encoding="utf-8-sig") or "[]")
    return {d["path"].lower(): d for d in (data if isinstance(data, list) else [data])}
