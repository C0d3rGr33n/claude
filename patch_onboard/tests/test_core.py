from pathlib import Path

from patch_onboard.differ import diff_files, diff_registry
from patch_onboard.downloader import detect_framework, pe_arch, sniff
from patch_onboard.installer import switch_plan
from patch_onboard.report import summarize
from patch_onboard.scraper import Candidate, InstallerScraper, classify_arch, pick_best
from patch_onboard.snapshot import Snapshot, decode_value, parse_files, parse_reg

REG_BEFORE = '''Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Foo]
"A"="1"
"B"=dword:00000001
'''
REG_AFTER = REG_BEFORE.replace('"A"="1"', '"A"="2"') + '''
[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{11111111-2222-3333-4444-555555555555}]
"DisplayName"="Acme App"
"DisplayVersion"="1.2.3"
"InstallLocation"="C:\\\\Program Files\\\\Acme\\\\"
"Path"=hex(2):43,00,3a,00,5c,00,\\
  00,00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\X]
"n"="noise"
'''


def test_classify_arch():
    assert classify_arch("app-x86_64-setup.exe") == "x64"
    assert classify_arch("AppSetup-win32.msi") == "x86"
    assert classify_arch("app_amd64.msi") == "x64"
    assert classify_arch("app-arm64.exe") == "arm64"
    assert classify_arch("app-1.64.2.exe") == "unknown"  # version digits are not an arch
    assert classify_arch("setup.exe", "", "Windows 64-bit") == "x64"


def test_pick_best_prefers_latest_stable_offline():
    c = InstallerScraper._rank([Candidate("u1", "app-2.0-x64-web.exe", "x64", "exe"),
               Candidate("u2", "app-2.0-x64.msi", "x64", "msi"),
               Candidate("u3", "app-1.9-x64.msi", "x64", "msi"),
               Candidate("u4", "app-2.1-beta-x64.exe", "x64", "exe"),
               Candidate("u5", "app-2.0-x86.exe", "x86", "exe")])
    best = pick_best([x for x in c if "beta" not in x.filename])
    assert best["x64"].url == "u2" and best["x86"].url == "u5"


def test_reg_parse_and_decode():
    r = parse_reg(REG_AFTER)
    k = r["hkey_local_machine\\software\\microsoft\\windows\\currentversion\\uninstall\\{11111111-2222-3333-4444-555555555555}"]
    assert decode_value(k[1]["path"][1]) == "C:\\"
    assert decode_value(k[1]["installlocation"][1]) == "C:\\Program Files\\Acme\\"
    assert decode_value("dword:0000000a") == 10
    assert decode_value("hex(7):61,00,00,00,62,00,00,00,00,00") == ["a", "b"]


def test_diff_and_summary():
    b, a = Snapshot(parse_reg(REG_BEFORE), parse_files("C:\\x.txt\t1\t1\n")), \
        Snapshot(parse_reg(REG_AFTER), parse_files(
            "C:\\x.txt\t2\t2\nC:\\Program Files\\Acme\\acme.exe\t900\t3\nC:\\Program Files\\Acme\\unins000.exe\t50\t3\n"
            "C:\\Windows\\Prefetch\\ACME.pf\t1\t1\n"))
    reg, files = diff_registry(b, a), diff_files(b, a)
    assert [m["after"] for m in reg["modified_values"]] == ["2"]
    assert not any("Defender" in k["key"] for k in reg["added_keys"])
    assert [f["path"] for f in files["added"]] == ["C:\\Program Files\\Acme\\acme.exe", "C:\\Program Files\\Acme\\unins000.exe"]
    det = {"c:\\program files\\acme\\acme.exe": {"path": "C:\\Program Files\\Acme\\acme.exe", "file_version": "1.2.3.0"}}
    s = summarize(reg, files, det)
    u = s["uninstall_entries"][0]
    assert u["DisplayName"] == "Acme App" and u["product_code"].startswith("{1111")
    assert s["main_executables"][0]["path"].endswith("acme.exe")
    assert {"type": "file_version", "path": "C:\\Program Files\\Acme\\acme.exe", "version": "1.2.3.0",
            "operator": "greater_or_equal"} in s["detection_rules"]


def _pe(tmp: Path, machine: int, extra=b"") -> Path:
    data = bytearray(b"MZ" + b"\0" * 0x3A + (0x40).to_bytes(4, "little") + b"PE\0\0" + machine.to_bytes(2, "little"))
    p = tmp / "s.exe"
    p.write_bytes(bytes(data) + extra)
    return p


def test_pe_and_framework(tmp_path):
    p = _pe(tmp_path, 0x8664, b"....Inno Setup Setup Data (6.2.0)")
    assert sniff(p) == "exe" and pe_arch(p) == "x64" and detect_framework(p) == "inno"
    plan = switch_plan({"kind": "exe", "framework": "inno"})
    assert plan[0].startswith("/VERYSILENT") and "/S" in plan
    assert switch_plan({"kind": "msi"})[0].startswith("/qn")


def test_scraper_offline(monkeypatch):
    pages = {
        "https://acme.com/": '<a href="/download">Download</a><a href="/mac">Mac</a>',
        "https://acme.com/download": '''
            <a href="https://cdn.acme-dl.net/AcmeSetup-3.1.0-x64.msi">Windows 64-bit</a>
            <a href="https://cdn.acme-dl.net/AcmeSetup-3.1.0-x86.exe">Windows 32-bit</a>
            <a href="https://cdn.acme-dl.net/Acme-3.1.0.dmg">macOS</a>
            <script>var u = "https:\\/\\/cdn.acme-dl.net\\/AcmeSetup-3.2.0-beta-x64.exe";</script>''',
    }
    s = InstallerScraper()
    monkeypatch.setattr(s, "_get_html", lambda u: pages.get(u, ""))
    best = pick_best(s.find("https://acme.com/"))
    assert best["x64"].filename == "AcmeSetup-3.1.0-x64.msi"  # newer beta ignored
    assert best["x86"].filename == "AcmeSetup-3.1.0-x86.exe"
