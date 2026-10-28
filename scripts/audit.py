#!/usr/bin/env python3
"""Offline, filename-only Python wheel/source-archive release audit.

Does not extract archives or execute their contents. Findings are leads for manual
review, not evidence that credentials leaked or archives are safe to install.
"""
from __future__ import annotations
import argparse
import json
import re
import stat
import sys
import tarfile
import zipfile
from pathlib import Path
from collections import Counter

SEVERITIES = ("low", "medium", "high", "critical")
RULES = {
    "PA001": "Unsafe, ambiguous, or traversal-like archive member path",
    "PA002": "Sensitive-looking filename is bundled in distribution",
    "PA003": "Build cache / repository metadata bundled in distribution",
    "PA004": "Required wheel .dist-info metadata is missing or ambiguous",
    "PA005": "Link entry in distribution archive needs review",
    "PA006": "Colliding or duplicate member pathname",
    "PA007": "Source distribution layout/metadata needs review",
}
SENSITIVE = re.compile(r"(?:^|/)(?:\.env(?:\.[^/]+)?|\.pypirc|\.npmrc|id_(?:rsa|dsa|ed25519)|credentials(?:\.[^/]+)?\.json|service[-_]account[^/]*\.json|[^/]+\.(?:pem|p12|pfx|key))(?:$|/)", re.I)
JUNK = re.compile(r"(?:^|/)(?:\.git|\.hg|\.svn|\.tox|\.pytest_cache|__pycache__|\.mypy_cache|\.DS_Store)(?:/|$)", re.I)
DRIVE = re.compile(r"^[a-zA-Z]:")

class AuditError(ValueError):
    pass


def check_path(name: str) -> bool:
    """Reject traversal even when a platform would normalize it differently."""
    return bool(not name or name.startswith(("/", "\\")) or "\\" in name
                or DRIVE.match(name) or "\x00" in name
                or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or any(x in (".", "..", "") for x in name.rstrip("/").split("/")))


def archive_type(path: Path) -> str:
    lower = path.name.lower()
    if lower.endswith(".whl"):
        return "wheel"
    if lower.endswith((".tar.gz", ".tgz", ".zip")):
        return "sdist"
    raise AuditError(f"Unsupported artifact suffix: {path.name} (expected .whl/.tar.gz/.tgz/.zip)")


def inspect(path: Path, max_archive_bytes: int = 50_000_000,
            max_entries: int = 5000, max_total_bytes: int = 500_000_000) -> dict:
    if path.is_symlink() or not path.is_file():
        raise AuditError("Input must be a regular, non-symlink archive")
    if path.stat().st_size > max_archive_bytes:
        raise AuditError(f"Archive exceeds compressed size cap of {max_archive_bytes} bytes")
    kind = archive_type(path)
    members = []
    try:
        if path.name.lower().endswith((".whl", ".zip")):
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()
                if len(infos) > max_entries:
                    raise AuditError(f"Archive exceeds {max_entries} entries")
                total = 0
                for info in infos:
                    total += info.file_size
                    if total > max_total_bytes:
                        raise AuditError(f"Declared uncompressed size exceeds {max_total_bytes} bytes")
                    if info.flag_bits & 1:
                        raise AuditError("Encrypted ZIP member: cannot verify archive")
                    mode = (info.external_attr >> 16) & 0xFFFF
                    link = stat.S_ISLNK(mode)
                    members.append((info.filename, info.is_dir(), link))
        else:
            with tarfile.open(path, "r:gz") as archive:
                total = 0
                for i, info in enumerate(archive):
                    if i >= max_entries:
                        raise AuditError(f"Archive exceeds {max_entries} entries")
                    total += info.size
                    if total > max_total_bytes:
                        raise AuditError(f"Declared uncompressed size exceeds {max_total_bytes} bytes")
                    members.append((info.name, info.isdir(), info.issym() or info.islnk()))
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile) as exc:
        raise AuditError(f"Unreadable or malformed distribution: {type(exc).__name__}") from exc

    findings = []
    def add(rule, severity, name, detail):
        findings.append({"rule": rule, "severity": severity, "path": name, "message": detail})

    normalized = Counter()
    names = set()
    for name, is_dir, link in members:
        if check_path(name):
            add("PA001", "critical", name, RULES["PA001"])
            continue
        clean = name.rstrip("/")
        if not is_dir:
            normalized[clean.casefold()] += 1
            names.add(clean)
            if SENSITIVE.search(clean):
                add("PA002", "high", clean, RULES["PA002"])
            if JUNK.search(clean):
                add("PA003", "medium", clean, RULES["PA003"])
        if link:
            add("PA005", "high", clean, RULES["PA005"])
    for canon, occurrences in sorted(normalized.items()):
        if occurrences > 1:
            add("PA006", "high", canon, f"Case-folded pathname appears {occurrences} times")
    if kind == "wheel":
        roots = sorted(set(n.split("/", 1)[0] for n in names if ".dist-info/" in n
                           and n.split("/", 1)[0].endswith(".dist-info")))
        if len(roots) != 1:
            add("PA004", "high", path.name, f"Expected exactly one root .dist-info directory; found {len(roots)}")
        else:
            root = roots[0]
            for part in ("METADATA", "WHEEL", "RECORD"):
                if root + "/" + part not in names:
                    add("PA004", "high", root, f"Missing {part}")
    else:
        files = [n for n in names if "/" in n]
        roots = {n.split("/", 1)[0] for n in files}
        if len(roots) != 1:
            add("PA007", "medium", path.name, "Source archive should have exactly one top-level source directory")
        elif roots:
            root = next(iter(roots))
            if root + "/PKG-INFO" not in names:
                add("PA007", "high", root, "Missing PKG-INFO (expected for modern sdists)")
            if root + "/pyproject.toml" not in names:
                add("PA007", "medium", root, "Missing pyproject.toml (may be a legacy sdist)")
    findings.sort(key=lambda f: (-SEVERITIES.index(f["severity"]), f["path"], f["rule"]))
    return {"archive": str(path), "artifact_type": kind, "entry_count": len(members), "findings": findings}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path, help="One or more .whl or .tar.gz/.zip artifacts")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default="high")
    args = parser.parse_args(argv)
    try:
        scans = [inspect(p) for p in args.archives]
    except AuditError as exc:
        print(f"INPUT ERROR: {exc}", file=sys.stderr)
        return 1
    findings = [dict(f, archive=scan["archive"]) for scan in scans for f in scan["findings"]]
    if args.format == "json":
        print(json.dumps({"tool": "python-artifact-audit", "scans": scans, "findings": findings}, indent=2))
    else:
        print("# Python Artifact Audit\n\nMetadata/name-only inspection; not proof of a safe distribution.\n")
        for scan in scans:
            print(f"## {scan['archive']} ({scan['artifact_type']}, {scan['entry_count']} entries)")
            for f in scan["findings"]:
                print(f"- **{f['severity'].upper()} {f['rule']}** `{f['path']}` — {f['message']}")
            if not scan["findings"]:
                print("- No findings in the supported rule set.")
    if args.fail_on != "none":
        floor = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f["severity"]) >= floor for f in findings):
            return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
