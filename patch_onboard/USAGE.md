# patch_onboard

Onboards a new Windows product for patch management:

1. Scrapes the official page (crawls same-site download pages, GitHub releases API, JS-embedded URLs) for `.exe`/`.msi` installers, classifies x64/x86, prefers latest stable, offline, MSI builds.
2. Downloads, verifies it is a real installer (MZ/OLE/zip), detects framework (Inno, NSIS, WiX Burn, InstallShield, Advanced Installer, Squirrel, ...) and arch (MSI Template, PE header). Picks a VM: x64 → x64 VM; x86 → x86 VM, else x64.
3. Reverts VM to its clean snapshot, takes **before** snapshot (`reg export` of HKLM\SOFTWARE, Services, Session Manager, HKCU, HKU\.DEFAULT + full C:\ walk).
4. Installs silently via WinRM with a per-framework switch matrix.
5. On failure (bad exit code, timeout/hung UI, "success" without an uninstall entry) reverts and retries with the next switch; 1618 waits for the MSI mutex and retries; 1633/1638 stop. Waits for child installers, kills auto-launched apps, reboots on 3010/pending renames, handles 1641 self-reboot. MSI log tail is captured on failure.
6. Takes **after** snapshot.
7. Diffs both (OS noise filtered).
8. Writes `report.json`: registry + file changes (file version, product version, company, SHA256, Authenticode signer), uninstall entries, product code, services, scheduled tasks, autoruns, env changes, shortcuts, main executables and suggested detection rules.

## Setup
```
pip install -r patch_onboard/requirements.txt
cp patch_onboard/vms.example.json vms.json   # edit
```
Guest VMs: WinRM enabled (`winrm quickconfig`), admin account, `LocalAccountTokenFilterPolicy=1` for non-builtin admins, a powered-on snapshot named `clean`. Host: `vmrun` (VMware) or Hyper-V PowerShell module.

## Run
```
python -m patch_onboard https://www.7-zip.org/ --config vms.json --out out/7zip
python -m patch_onboard <url> --config vms.json --scan-only          # just list installers
python -m patch_onboard <url> --config vms.json --installer-url <direct .msi/.exe>
python -m patch_onboard <url> --config vms.json --render             # JS-heavy sites (playwright)
```
Exit code 0 if at least one installer was installed and analysed.

## Tests
`python -m pytest patch_onboard/tests`
