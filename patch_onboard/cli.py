"""CLI: python -m patch_onboard <product_url> --config vms.json"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .config import load_config
from .pipeline import onboard


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="patch_onboard", description="Onboard a Windows product for patch management")
    ap.add_argument("product_url", help="official product / download page URL")
    ap.add_argument("--config", required=True, help="VM inventory JSON (see vms.example.json)")
    ap.add_argument("--out", default="onboard_out", help="output directory")
    ap.add_argument("--arch", choices=["x64", "x86", "all"], default="all")
    ap.add_argument("--installer-url", action="append", help="skip scraping, use this installer URL (repeatable)")
    ap.add_argument("--render", action="store_true", help="render JS pages with Playwright/Chromium")
    ap.add_argument("--scan-only", action="store_true", help="only list installers found, no VM work")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    archs = ("x64", "x86") if a.arch == "all" else (a.arch,)
    out = Path(a.out)
    if a.scan_only:
        from .scraper import InstallerScraper, pick_best
        cands = InstallerScraper(render=a.render).find(a.product_url)
        print(json.dumps({"best": {k: c.to_dict() for k, c in pick_best(cands, archs).items()},
                          "all": [c.to_dict() for c in cands]}, indent=2))
        return 0

    result = onboard(a.product_url, load_config(a.config), out, archs, a.installer_url, a.render)
    out.mkdir(parents=True, exist_ok=True)
    report = out / "report.json"
    report.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    for e in result["installers"]:
        s = e.get("summary", {})
        print(f"[{e['candidate']['arch']}] {e.get('status', e.get('error', e.get('skipped')))} "
              f"{e.get('silent_command', '')}")
        for u in s.get("uninstall_entries", []):
            print(f"    {u.get('DisplayName')} {u.get('DisplayVersion')}  ({u['key']})")
    print(f"report: {report}")
    return 0 if any(e.get("status") == "installed" for e in result["installers"]) else 1
