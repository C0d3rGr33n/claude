"""Turn raw diffs into patch-management facts (uninstall entry, detection rules...)."""
from __future__ import annotations

import os
import re

UNINSTALL_RE = re.compile(r"\\Windows\\CurrentVersion\\Uninstall\\([^\\]+)$", re.I)
SERVICE_RE = re.compile(r"\\CurrentControlSet\\Services\\([^\\]+)$", re.I)
TASK_RE = re.compile(r"\\Schedule\\TaskCache\\Tree\\(.+)$", re.I)
RUN_RE = re.compile(r"\\CurrentVersion\\Run(Once)?$", re.I)
GUID_RE = re.compile(r"^\{[0-9A-F-]{36}\}$", re.I)
UNINSTALL_FIELDS = ("DisplayName", "DisplayVersion", "Publisher", "InstallLocation", "InstallDate",
                    "UninstallString", "QuietUninstallString", "WindowsInstaller", "EstimatedSize")


def summarize(reg: dict, files: dict, details: dict) -> dict:
    uninstall = []
    for k in reg["added_keys"]:
        m = UNINSTALL_RE.search(k["key"])
        if m:
            vals = {f: k["values"].get(f) for f in UNINSTALL_FIELDS if f in k["values"]}
            uninstall.append({"key": k["key"], "product_code": m.group(1) if GUID_RE.match(m.group(1)) else None,
                              "wow6432": "\\wow6432node\\" in k["key"].lower(), **vals})
    services = [{"name": SERVICE_RE.search(k["key"]).group(1),
                 **{f: k["values"].get(f) for f in ("DisplayName", "ImagePath", "Start", "ObjectName")}}
                for k in reg["added_keys"] if SERVICE_RE.search(k["key"])]
    tasks = [TASK_RE.search(k["key"]).group(1) for k in reg["added_keys"] if TASK_RE.search(k["key"])]
    autoruns = [v for v in reg["added_values"] if RUN_RE.search(v["key"])]
    env = [v for v in reg["modified_values"] + reg["added_values"] if v["key"].lower().endswith("\\environment")]

    added = [f["path"] for f in files["added"]]
    install_dirs = _install_dirs(added, uninstall)
    exes = sorted((details.get(p.lower(), {"path": p}) | {"size": s}
                   for p, s in ((f["path"], f["size"]) for f in files["added"])
                   if p.lower().endswith(".exe") and any(p.lower().startswith(d.lower()) for d in install_dirs)),
                  key=lambda d: (not _is_main(d, uninstall), -d["size"]))
    shortcuts = [p for p in added if p.lower().endswith(".lnk")]

    return {
        "uninstall_entries": uninstall,
        "install_dirs": install_dirs,
        "main_executables": exes[:5],
        "services": services,
        "scheduled_tasks": tasks,
        "autoruns": autoruns,
        "environment_changes": env,
        "shortcuts": shortcuts,
        "detection_rules": _detection(uninstall, exes),
        "counts": {k: len(v) for k, v in reg.items()} | {f"files_{k}": len(v) for k, v in files.items()},
    }


def _install_dirs(added: list[str], uninstall: list[dict]) -> list[str]:
    dirs = {u["InstallLocation"].rstrip("\\") for u in uninstall if u.get("InstallLocation")}
    roots = re.compile(r"^(c:\\program files( \(x86\))?|c:\\programdata|c:\\users\\[^\\]+\\appdata\\"
                       r"(local\\programs|local|roaming))\\[^\\]+", re.I)
    counts: dict[str, int] = {}
    for p in added:
        m = roots.match(p)
        if m:
            counts[m.group(0)] = counts.get(m.group(0), 0) + 1
    dirs |= {d for d, n in counts.items() if n >= 2 or d.lower().startswith("c:\\program files")}
    return sorted(dirs)


def _is_main(d: dict, uninstall: list[dict]) -> bool:
    name = os.path.basename(d["path"]).lower()
    if re.search(r"unins|uninstall|update|crash|helper|elevat", name):
        return False
    product = " ".join(str(u.get("DisplayName", "")) for u in uninstall).lower()
    pn = (d.get("product_name") or "").lower()
    return bool(product) and (name[:-4] in product.replace(" ", "") or bool(pn and pn in product))


def _detection(uninstall: list[dict], exes: list[dict]) -> list[dict]:
    rules = []
    for u in uninstall:
        hive = "HKLM" if u["key"].upper().startswith("HKEY_LOCAL_MACHINE") else "HKCU"
        rules.append({"type": "registry", "hive": hive, "key": u["key"].split("\\", 1)[1],
                      "value": "DisplayVersion", "version": u.get("DisplayVersion"), "operator": "greater_or_equal"})
        if u.get("product_code"):
            rules.append({"type": "msi_product_code", "product_code": u["product_code"],
                          "version": u.get("DisplayVersion")})
    if exes and exes[0].get("file_version"):
        rules.append({"type": "file_version", "path": exes[0]["path"], "version": exes[0]["file_version"],
                      "operator": "greater_or_equal"})
    return rules
