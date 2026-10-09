"""End-to-end onboarding: scrape -> download -> VM -> snapshot -> install (retry) -> snapshot -> diff."""
from __future__ import annotations

import logging
import time
from dataclasses import asdict
from pathlib import Path

from . import downloader, installer
from .config import Config, VMConfig
from .differ import diff_files, diff_registry
from .report import summarize
from .scraper import Candidate, InstallerScraper, classify_arch, pick_best
from .snapshot import file_details, take_snapshot
from .vm import Guest, hypervisor_for, ps_quote

log = logging.getLogger(__name__)


def onboard(product_url: str, cfg: Config, out_dir: Path, archs=("x64", "x86"),
            installer_urls: list[str] | None = None, render: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {"product_url": product_url, "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "installers": []}

    if installer_urls:  # manual override skips scraping
        cands = [Candidate(u, u.rsplit("/", 1)[-1], classify_arch(u), u.rsplit(".", 1)[-1].lower())
                 for u in installer_urls]
        chosen = {c.arch if c.arch != "unknown" else f"unknown{i}": c for i, c in enumerate(cands)}
    else:
        cands = InstallerScraper(render=render).find(product_url)
        chosen = pick_best(cands, archs)
    result["candidates_found"] = [c.to_dict() for c in cands[:50]]
    if not chosen:
        result["error"] = "no Windows .exe/.msi installer found (try --render or --installer-url)"
        return result

    seen_hashes = set()
    for arch, cand in chosen.items():
        entry = {"candidate": cand.to_dict()}
        result["installers"].append(entry)
        try:
            local = downloader.download(cand.url, out_dir / "downloads" / arch)
            info = downloader.inspect(local, cand.arch)
            entry["installer"] = info
            if info["sha256"] in seen_hashes:  # same universal installer listed twice
                entry["skipped"] = "duplicate of another arch's installer"
                continue
            seen_hashes.add(info["sha256"])
            vm = cfg.pick_vm(info["arch"])
            entry["vm"] = {"name": vm.name, "arch": vm.arch}
            entry.update(_install_and_diff(vm, cfg, local, info, out_dir))
        except Exception as e:  # noqa: BLE001 - keep other arches going
            log.exception("onboarding %s failed", arch)
            entry["error"] = f"{type(e).__name__}: {e}"
    result["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    return result


def _prepare(vm: VMConfig, guest: Guest, hv, local: Path, s) -> str:
    hv.revert()
    guest.wait_ready(s.ready_timeout)
    guest.ps(f"New-Item -ItemType Directory -Force {ps_quote(vm.work_dir)} | Out-Null")
    remote = f"{vm.work_dir}\\{local.name}"
    guest.copy_to(str(local), remote)
    return remote


def _install_and_diff(vm: VMConfig, cfg: Config, local: Path, info: dict, out_dir: Path) -> dict:
    s = cfg.settings
    guest, hv = Guest(vm), hypervisor_for(vm)
    snap_dir = out_dir / "snapshots"
    snap_dir.mkdir(parents=True, exist_ok=True)

    remote = _prepare(vm, guest, hv, local, s)
    before = take_snapshot(guest, vm.work_dir, s.file_excludes, "before", snap_dir)  # reused for retries

    attempts, success = [], None
    plan = installer.switch_plan(info)
    i, retried_busy = 0, set()
    while i < len(plan):
        if attempts:  # every retry starts from the clean snapshot
            remote = _prepare(vm, guest, hv, local, s)
        att = installer.run_attempt(guest, remote, info, plan[i], vm.work_dir,
                                    s.install_timeout, s.settle_timeout, s.ready_timeout)
        attempts.append(asdict(att))
        log.info("attempt %d: exit=%s (%s) ok=%s", len(attempts), att.exit_code, att.meaning, att.ok)
        if att.ok:
            success = att
            break
        if att.exit_code in (1633,):            # wrong platform: no switch will fix it
            break
        if att.exit_code == 1618 and i not in retried_busy:
            retried_busy.add(i)                 # MSI busy: retry same switch once after revert
            installer.wait_msi_idle(guest, 900)
            continue
        if att.exit_code == 1638:               # pre-installed in snapshot: diff would be meaningless
            break
        i += 1

    res = {"attempts": attempts, "status": "installed" if success else "failed"}
    if not success:
        return res

    res["silent_command"] = success.command
    if success.reboot_required and s.reboot_if_required and success.exit_code != 1641:
        log.info("%s: rebooting to complete install", vm.name)
        guest.reboot(s.ready_timeout)
        res["rebooted"] = True

    after = take_snapshot(guest, vm.work_dir, s.file_excludes, "after", snap_dir)
    reg = diff_registry(before, after, s.extra_reg_noise)
    files = diff_files(before, after, s.extra_file_noise)

    targets = [f["path"] for f in files["added"] + files["modified"]][: s.max_detail_files]
    details = file_details(guest, vm.work_dir, targets)
    for f in files["added"] + files["modified"]:
        f.update({k: v for k, v in details.get(f["path"].lower(), {}).items() if k != "path"})

    res["summary"] = summarize(reg, files, details)
    res["registry_changes"] = reg
    res["file_changes"] = files
    return res
