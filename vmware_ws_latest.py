#!/usr/bin/env python3
"""Find the latest VMware Workstation Pro release and print its build number.

Reads VMware's update repository directory listing
(softwareupdate.vmware.com/cds/vmw-desktop/ws/<version>/<build>/<os>/).
Reuses jabber_latest's fetchers: browser-like requests, Playwright fallback.
"""
import argparse
import re
import sys
from urllib.parse import urljoin

import requests

import jabber_latest as jl

CDS_URL = "https://softwareupdate.vmware.com/cds/vmw-desktop/ws/"
DIR_RE = re.compile(r'<a\b[^>]*href="([^"?/][^"]*?)/?"', re.I)


def die(msg):
    sys.exit(f"ERROR: {msg}")


def vkey(v):
    """Numeric sort key; handles '17.6.3' and '25H2'-style names."""
    return tuple(int(x) for x in re.findall(r"\d+", v))


def matches(version, prefix):
    return not prefix or vkey(version)[:len(vkey(prefix))] == vkey(prefix)


def subdirs(fetcher, url):
    """Child directory names of an Apache/nginx-style listing."""
    html = fetcher.get(url).decode("utf-8", "replace")
    names = {h.rstrip("/") for h in DIR_RE.findall(html)}
    return sorted(n for n in names if not n.startswith(("http", "#", "..")) and "/" not in n)


def run(fetcher, prefix=None, list_only=False):
    versions = [v for v in subdirs(fetcher, CDS_URL) if re.match(r"\d", v)]
    if not versions:
        die(f"no version directories found at {CDS_URL}")
    if list_only:
        return sorted(versions, key=vkey, reverse=True)
    pool = [v for v in versions if matches(v, prefix)]
    if not pool:
        die(f"no release matching '{prefix}'. Available: "
            + ", ".join(sorted(versions, key=vkey, reverse=True)))
    version = max(pool, key=vkey)
    vurl = urljoin(CDS_URL, version + "/")
    builds = [b for b in subdirs(fetcher, vurl) if b.isdigit()]
    if not builds:
        die(f"no build directory found under {vurl}")
    build = max(builds, key=int)
    burl = urljoin(vurl, build + "/")
    platforms = [p for p in subdirs(fetcher, burl) if p.isalpha()]
    return version, build, burl, platforms


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version", nargs="?", help="only consider this line, e.g. 17 or 17.6")
    ap.add_argument("--list", action="store_true", help="list all versions found and exit")
    args = ap.parse_args()

    fetchers = [jl.RequestsFetcher, jl.PlaywrightFetcher]
    for make in fetchers:
        try:
            f = make()
        except RuntimeError as e:
            print(f"[skip] {e}", file=sys.stderr)
            continue
        try:
            result = run(f, args.version, args.list)
            break
        except jl.Blocked as e:
            print(f"[{f.name}] Access Denied at {e.args[0]}; falling back...", file=sys.stderr)
        except (requests.RequestException, RuntimeError) as e:
            die(f"network error via {f.name}: {e}")
        finally:
            f.close()
    else:
        die("blocked with every method")

    if args.list:
        print("\n".join(result))
        return
    version, build, url, platforms = result
    label = f"Latest {args.version}.x version" if args.version else "Latest version"
    print(f"VMware Workstation Pro\n{label}: {version}\nBuild: {build}\n"
          f"Full: {version}-{build}\nPlatforms: {', '.join(platforms) or 'n/a'}\nURL: {url}")


if __name__ == "__main__":
    main()
