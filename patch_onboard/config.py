"""VM inventory and run settings, loaded from a JSON file."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields


@dataclass
class VMConfig:
    name: str
    arch: str                      # "x64" | "x86"
    host: str                      # guest hostname/IP reachable over WinRM
    username: str
    password: str = ""
    password_env: str = ""         # read password from this env var instead
    hypervisor: str = "vmware"     # "vmware" | "hyperv" | "none"
    vm_id: str = ""                # .vmx path (vmware) or VM name (hyperv)
    clean_snapshot: str = "clean"
    vmrun_path: str = "vmrun"
    winrm_port: int = 5985
    winrm_ssl: bool = False
    winrm_auth: str = "ntlm"
    work_dir: str = r"C:\PatchOnboard"

    def __post_init__(self):
        self.arch = self.arch.lower()
        if self.password_env and not self.password:
            self.password = os.environ.get(self.password_env, "")


@dataclass
class Settings:
    install_timeout: int = 1200        # seconds per install attempt
    settle_timeout: int = 300          # wait for child installer processes
    ready_timeout: int = 600           # wait for VM/WinRM after revert/reboot
    reboot_if_required: bool = True
    max_detail_files: int = 5000       # cap on version/hash lookups
    file_excludes: list[str] = field(default_factory=lambda: [
        r"C:\Windows\WinSxS\Backup", r"C:\Windows\Prefetch",
        r"C:\System Volume Information", r"C:\$Recycle.Bin",
    ])
    extra_file_noise: list[str] = field(default_factory=list)
    extra_reg_noise: list[str] = field(default_factory=list)


@dataclass
class Config:
    vms: list[VMConfig]
    settings: Settings

    def pick_vm(self, arch: str) -> VMConfig:
        """x64 installer -> x64 VM. x86 installer -> x86 VM, else x64 (WOW64)."""
        order = {"x64": ["x64"], "x86": ["x86", "x64"], "arm64": ["arm64"]}.get(arch, ["x64", "x86"])
        for want in order:
            for vm in self.vms:
                if vm.arch == want:
                    return vm
        raise LookupError(f"No VM configured for {arch} installer")


def _build(cls, data: dict):
    known = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in known})


def load_config(path: str) -> Config:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    return Config(
        vms=[_build(VMConfig, v) for v in raw["vms"]],
        settings=_build(Settings, raw.get("settings", {})),
    )
