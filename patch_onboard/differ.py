"""Compare two snapshots, dropping known OS noise."""
from __future__ import annotations

import re

from .snapshot import Snapshot, decode_value

FILE_NOISE = [
    r"^c:\\windows\\(prefetch|logs|temp|softwaredistribution|servicing|panther|debug)\\",
    r"^c:\\windows\\system32\\(winevt|logfiles|sru|config|wdi|tasks\\microsoft)\\",
    r"^c:\\windows\\(serviceprofiles|appcompat|inf\\setupapi)",
    r"^c:\\programdata\\microsoft\\(windows defender|windows\\wer|diagnosis|network|search|windows\\appRepository)\\",
    r"\\appdata\\local\\(temp|microsoft\\windows\\(explorer|inetcache|webcache|history|caches))\\",
    r"\\appdata\\local\\(packages|connecteddevicesplatform|d3dscache)\\",
    r"\\appdata\\roaming\\microsoft\\windows\\recent\\",
    r"\\ntuser\.dat", r"\\usrclass\.dat", r"\.(etl|evtx|blf|regtrans-ms|tmp|log1|log2)$",
    r"^c:\\windows\\installer\\(config\.msi|\{[^\\]+\}\\.*\.tmp$)",
]
REG_NOISE = [
    r"\\microsoft\\windows defender", r"\\microsoft\\cryptography\\rng",
    r"\\windows nt\\currentversion\\(prefetcher|perflib|notifications|winlogon\\notifications)",
    r"\\microsoft\\systemcertificates\\authroot", r"\\services\\(bam|dam|tcpip|nla|w32time)\\",
    r"\\currentversion\\(diagnostics|windowsupdate|cloudstore|explorer\\(userassist|recentdocs|"
    r"sessioninfo|feature|bags|shellbags|startuprun))", r"\\tracing\\", r"\\winevt\\",
    r"\\microsoft\\(radar|sqmclient|wbem\\cimom|ole\\extensions|input|speech_onecore|wsman)",
    r"\\currentversion\\(appmodel|appx|backgroundmodel|capabilityaccessmanager|storage)",
    r"\\session manager\\(memory management|power)", r"\\services\\\w+\\(state|parameters\\stats)",
    r"\\microsoft\\windows\\currentversion\\(shell extensions\\cached|group policy)",
    r"\\windows\\shell\\(bags|bagmru)", r"\\microsoft\\windows search",
]


def _rx(patterns):
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.I)


def diff_registry(before: Snapshot, after: Snapshot, extra_noise=()) -> dict:
    noise = _rx(REG_NOISE + list(extra_noise))
    b, a = before.registry, after.registry
    out = {"added_keys": [], "removed_keys": [], "added_values": [], "removed_values": [], "modified_values": []}
    for k in sorted(a.keys() - b.keys()):
        name, vals = a[k]
        if not noise.search(k):
            out["added_keys"].append({"key": name, "values": {n: decode_value(v) for n, v in vals.values()}})
    for k in sorted(b.keys() - a.keys()):
        if not noise.search(k):
            out["removed_keys"].append(b[k][0])
    for k in sorted(a.keys() & b.keys()):
        if noise.search(k):
            continue
        key, av = a[k]
        bv = b[k][1]
        for n in av.keys() - bv.keys():
            out["added_values"].append({"key": key, "name": av[n][0], "value": decode_value(av[n][1])})
        for n in bv.keys() - av.keys():
            out["removed_values"].append({"key": key, "name": bv[n][0], "value": decode_value(bv[n][1])})
        for n in av.keys() & bv.keys():
            if av[n][1] != bv[n][1]:
                out["modified_values"].append({"key": key, "name": av[n][0], "before": decode_value(bv[n][1]),
                                               "after": decode_value(av[n][1])})
    return out


def diff_files(before: Snapshot, after: Snapshot, extra_noise=()) -> dict:
    noise = _rx(FILE_NOISE + list(extra_noise))
    b, a = before.files, after.files
    rec = lambda t: {"path": t[0], "size": t[1]}  # noqa: E731
    return {
        "added": [rec(a[p]) for p in sorted(a.keys() - b.keys()) if not noise.search(p)],
        "removed": [rec(b[p]) for p in sorted(b.keys() - a.keys()) if not noise.search(p)],
        "modified": [{"path": a[p][0], "size_before": b[p][1], "size": a[p][1]}
                     for p in sorted(a.keys() & b.keys())
                     if a[p][1:] != b[p][1:] and not noise.search(p)],
    }
