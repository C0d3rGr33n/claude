"""Silent-switch matrix and a single monitored install attempt inside the guest."""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

from .vm import Guest, ps_quote

log = logging.getLogger(__name__)

# Ordered fallbacks per packaging framework. {log} = guest log path.
EXE_SWITCHES = {
    "inno": ["/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /ALLUSERS /LOG={log}",
             "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG={log}", "/SILENT /NORESTART"],
    "nsis": ["/S /ALLUSERS", "/S", "/S /AllUsers=1"],
    "wixburn": ["/quiet /norestart /log {log}", "/install /quiet /norestart /log {log}", "/passive /norestart"],
    "installshield": ['/s /v"/qn /norestart /l*v \\"{log}\\""', "/s /v/qn", "/s", "-s"],
    "advinst": ["/exenoui /qn /norestart /l*v {log}", "/quiet /norestart", "/exenoui /quiet"],
    "squirrel": ["--silent", "-s"],
    "installaware": ["/s", "/s /l={log}"],
    "wise": ["/s"],
    "setupfactory": ["/S"],
    "7zsfx": ["-y -gm2", "/S"],
}
GENERIC_SWITCHES = ["/quiet /norestart", "/S", "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
                    "/s", "/silent", "/qn", "--silent", "-q"]
MSI_SWITCHES = ["/qn /norestart ALLUSERS=1 /l*v {log}",
                "/qn /norestart REBOOT=ReallySuppress /l*v {log}",
                "/qn /norestart ALLUSERS=2 MSIINSTALLPERUSER= /l*v {log}",
                "/passive /norestart /l*v {log}"]

SUCCESS = {0, 3010, 1641}
REBOOT = {3010, 1641}
EXIT_MEANING = {
    0: "success", 3010: "success, reboot required", 1641: "success, reboot initiated",
    1601: "Windows Installer service inaccessible", 1602: "user cancelled", 1603: "fatal error during install",
    1618: "another install in progress", 1619: "package could not be opened", 1620: "invalid package",
    1625: "blocked by policy", 1633: "unsupported platform/arch", 1638: "another version already installed",
    1639: "invalid command line", 1925: "insufficient privileges", -1: "timeout (installer hung / waiting for UI)",
    2: "file not found / invalid args (generic)", 5: "access denied",
}
INSTALLER_PROC_RE = re.compile(r"msiexec|setup|install|unins|^is-|\.tmp$|nsis|_iu14d2n|au_\.exe|vcredist|"
                               r"ndp\d|dotnet|wusa|dism|tiworker|trustedinstaller|bootstrap", re.I)
SYSTEM_PROCS = {"svchost.exe", "conhost.exe", "wsmprovhost.exe", "wmiprvse.exe", "dllhost.exe", "msiexec.exe",
                "searchprotocolhost.exe", "searchfilterhost.exe", "backgroundtaskhost.exe", "runtimebroker.exe",
                "taskhostw.exe", "sppsvc.exe", "tiworker.exe", "trustedinstaller.exe", "mpcmdrun.exe",
                "msmpeng.exe", "smartscreen.exe", "compattelrunner.exe", "powershell.exe", "audiodg.exe"}

VERIFY_PS = r"""
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$u = @(foreach ($p in $k) { Get-ChildItem $p -ErrorAction SilentlyContinue | % { $_.Name } })
$pend = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
ConvertTo-Json -Compress -InputObject @{uninstall=$u; pending_reboot=$pend}
"""

RUN_PS = r"""
Unblock-File -LiteralPath __FILE__ -ErrorAction SilentlyContinue
$p = Start-Process -FilePath __EXE__ -ArgumentList __ARGS__ -PassThru -WindowStyle Hidden
$null = $p.Handle
if ($p.WaitForExit(__MS__)) { $p.ExitCode } else { & taskkill.exe /PID $p.Id /T /F | Out-Null; 'TIMEOUT' }
"""


@dataclass
class Attempt:
    command: str
    exit_code: int | None = None
    meaning: str = ""
    duration: float = 0.0
    new_uninstall_keys: list = field(default_factory=list)
    reboot_required: bool = False
    auto_launched: list = field(default_factory=list)
    log_tail: list = field(default_factory=list)
    ok: bool = False
    note: str = ""


def switch_plan(info: dict) -> list[str]:
    if info["kind"] == "msi":
        return MSI_SWITCHES
    fw = EXE_SWITCHES.get(info.get("framework", "unknown"), [])
    return list(dict.fromkeys(fw + GENERIC_SWITCHES))


def wait_msi_idle(guest: Guest, timeout: int = 600):
    """Wait for Windows Installer mutex (avoids 1618)."""
    end = time.time() + timeout
    while time.time() < end:
        busy = guest.ps("try { $m=[Threading.Mutex]::OpenExisting('Global\\_MSIExecute'); $m.Dispose(); 1 } catch { 0 }").strip()
        if busy == "0":
            return
        time.sleep(10)


def run_attempt(guest: Guest, remote_file: str, info: dict, switches: str, work_dir: str,
                timeout: int, settle_timeout: int, ready_timeout: int = 600) -> Attempt:
    log_path = f"{work_dir}\\install_{int(time.time())}.log"
    args = switches.format(log=log_path)
    if info["kind"] == "msi":
        exe, args = "msiexec.exe", f'/i "{remote_file}" {args}'
    else:
        exe = remote_file
    att = Attempt(command=f'"{exe}" {args}')
    log.info("%s: installing -> %s", guest.vm.name, att.command)

    before_procs = {p["pid"] for p in guest.processes()}
    before_un = set(guest.ps_json(VERIFY_PS)["uninstall"])
    wait_msi_idle(guest)
    t0 = time.time()
    out = guest.ps(RUN_PS.replace("__FILE__", ps_quote(remote_file)).replace("__EXE__", ps_quote(exe))
                   .replace("__ARGS__", ps_quote(args)).replace("__MS__", str(timeout * 1000))).strip()
    att.exit_code = -1 if out.endswith("TIMEOUT") else int(out.splitlines()[-1])
    att.meaning = EXIT_MEANING.get(att.exit_code, "installer specific error")

    if att.exit_code == 1641:  # installer is rebooting the VM itself
        time.sleep(30)
        guest.wait_ready(ready_timeout)
    elif att.exit_code in SUCCESS:
        att.auto_launched = _settle(guest, before_procs, settle_timeout)
    att.duration = round(time.time() - t0, 1)

    state = guest.ps_json(VERIFY_PS)
    att.new_uninstall_keys = sorted(set(state["uninstall"]) - before_un)
    att.reboot_required = att.exit_code in REBOOT or bool(state["pending_reboot"])
    att.ok = att.exit_code in SUCCESS and bool(att.new_uninstall_keys)
    if att.exit_code in SUCCESS and not att.new_uninstall_keys:
        att.note = "exit code success but no uninstall entry appeared (switch ignored / extract-only?)"
    if not att.ok:
        att.log_tail = _log_tail(guest, log_path)
    return att


def _is_installer(p: dict) -> bool:
    name = (p["name"] or "").lower()
    if name == "msiexec.exe":
        return not p["service"]  # the msiserver service instance is always there
    return bool(INSTALLER_PROC_RE.search(name))


def _settle(guest: Guest, baseline: set, timeout: int) -> list[str]:
    """Wait for spawned installer children; kill apps auto-launched after setup."""
    end = time.time() + timeout
    while True:
        new = [p for p in guest.processes() if p["pid"] not in baseline]
        if not any(_is_installer(p) for p in new) or time.time() > end:
            break
        time.sleep(5)
    killed = [p for p in new if not p["service"] and (p["name"] or "").lower() not in SYSTEM_PROCS
              and p["path"] and not p["path"].lower().startswith("c:\\windows\\")]
    for p in killed:
        guest.ps(f"Stop-Process -Id {p['pid']} -Force -ErrorAction SilentlyContinue", check=False)
    return [p["path"] for p in killed]


def _log_tail(guest: Guest, log_path: str, n: int = 40) -> list[str]:
    script = (f"if (Test-Path {ps_quote(log_path)}) {{ $l = Get-Content {ps_quote(log_path)}; "
              "$i = ($l | Select-String 'Return value 3' | Select -First 1).LineNumber; "
              f"if ($i) {{ $l[[Math]::Max(0,$i-{n})..($i)] }} else {{ $l | Select -Last {n} }} }}")
    try:
        return guest.ps(script, check=False).splitlines()
    except Exception:  # noqa: BLE001
        return []
