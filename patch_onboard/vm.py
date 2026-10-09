"""Hypervisor control (revert/start) and guest operations over WinRM."""
from __future__ import annotations

import json
import logging
import subprocess
import time

from .config import VMConfig

log = logging.getLogger(__name__)


def ps_quote(s: str) -> str:
    """Single-quoted PowerShell literal."""
    return "'" + s.replace("'", "''") + "'"


class Hypervisor:
    def __init__(self, vm: VMConfig):
        self.vm = vm

    def revert(self):  # pragma: no cover - needs a hypervisor
        raise NotImplementedError

    @staticmethod
    def _run(cmd: list[str], check=True):
        log.debug("host: %s", " ".join(cmd))
        r = subprocess.run(cmd, capture_output=True, text=True)
        if check and r.returncode:
            raise RuntimeError(f"{cmd[0]} failed: {r.stdout}{r.stderr}")
        return r


class VMware(Hypervisor):
    def revert(self):
        v = self.vm
        self._run([v.vmrun_path, "-T", "ws", "revertToSnapshot", v.vm_id, v.clean_snapshot])
        self._run([v.vmrun_path, "-T", "ws", "start", v.vm_id, "nogui"], check=False)  # no-op if running


class HyperV(Hypervisor):
    def revert(self):
        n, s = ps_quote(self.vm.vm_id), ps_quote(self.vm.clean_snapshot)
        self._run(["powershell", "-NoProfile", "-Command",
                   f"Restore-VMSnapshot -VMName {n} -Name {s} -Confirm:$false; "
                   f"if ((Get-VM -Name {n}).State -ne 'Running') {{ Start-VM -Name {n} }}"])


class NoHypervisor(Hypervisor):
    def revert(self):
        log.warning("%s: no hypervisor -> cannot revert; retries run on a dirty machine", self.vm.name)


def hypervisor_for(vm: VMConfig) -> Hypervisor:
    return {"vmware": VMware, "hyperv": HyperV, "none": NoHypervisor}[vm.hypervisor](vm)


class Guest:
    """Thin wrapper around pypsrp; WinRM runs elevated for local admins
    (needs LocalAccountTokenFilterPolicy=1 for non-builtin admin accounts)."""

    def __init__(self, vm: VMConfig):
        self.vm = vm
        self._client = None

    @property
    def client(self):
        if self._client is None:
            from pypsrp.client import Client
            self._client = Client(self.vm.host, username=self.vm.username, password=self.vm.password,
                                  port=self.vm.winrm_port, ssl=self.vm.winrm_ssl, auth=self.vm.winrm_auth,
                                  cert_validation=False, operation_timeout=60, read_timeout=90)
        return self._client

    def reset(self):
        self._client = None

    def ps(self, script: str, check: bool = True) -> str:
        out, streams, had_errors = self.client.execute_ps(script)
        if had_errors and check:
            errs = "; ".join(str(e) for e in streams.error)
            raise RuntimeError(f"guest PowerShell error: {errs}")
        return out

    def ps_json(self, script: str):
        out = self.ps(script).strip()
        return json.loads(out) if out else None

    def copy_to(self, local: str, remote: str):
        self.client.copy(local, remote)

    def fetch(self, remote: str, local: str):
        self.client.fetch(remote, local)

    def wait_ready(self, timeout: int):
        self.reset()
        end = time.time() + timeout
        while time.time() < end:
            try:
                # Explorer/TrustedInstaller settling avoids 1618 + noisy diffs
                self.ps("$null = Get-Service winmgmt; Start-Sleep 1")
                log.info("%s: WinRM ready", self.vm.name)
                return
            except Exception as e:  # noqa: BLE001 - VM still booting
                log.debug("waiting for %s: %s", self.vm.host, e)
                self.reset()
                time.sleep(10)
        raise TimeoutError(f"{self.vm.name} not reachable over WinRM after {timeout}s")

    def reboot(self, timeout: int):
        try:
            self.ps("Restart-Computer -Force", check=False)
        except Exception:  # noqa: BLE001 - connection drops on reboot
            pass
        time.sleep(30)
        self.wait_ready(timeout)

    def processes(self) -> list[dict]:
        return self.ps_json(
            "$svc = @(Get-CimInstance Win32_Service | ? ProcessId -gt 0 | % ProcessId); "
            "$p = @(Get-CimInstance Win32_Process | % { [pscustomobject]@{pid=[int]$_.ProcessId; "
            "name=$_.Name; path=$_.ExecutablePath; service=($svc -contains $_.ProcessId)} }); "
            "ConvertTo-Json -Compress -InputObject $p") or []
