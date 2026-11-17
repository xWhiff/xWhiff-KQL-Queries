#!/usr/bin/env python3
"""Header check, README catalogue and MITRE ATT&CK coverage layer for hunting-grounds.

Usage (from the repo root):
    python3 .github/scripts/kql_catalogue.py build            # rewrite README catalogue + attack-coverage.json
    python3 .github/scripts/kql_catalogue.py build --check    # fail if they are out of date (used in CI)
    python3 .github/scripts/kql_catalogue.py headers --base origin/main
        # check query headers: files changed vs --base must pass (errors),
        # every other query only gets a warning, so old queries don't block PRs.

Standard library only, so it runs on any machine with Python 3.9+.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"
LAYER = REPO / "attack-coverage.json"
QUERY_FOLDERS = ["Threat Hunting", "Detection", "Investigation", "Baselines", "Templates"]

# Header fields every query must have, and the allowed values for Type.
REQUIRED = ["Title", "Type", "Platform", "Description", "MITRE ATT&CK", "Data sources", "Author", "Created", "Version"]
KNOWN = REQUIRED + ["References", "How to use", "Tuning / FPs", "Updated"]
TYPES = {"Threat Hunting", "Detection", "Investigation", "Baseline", "Template"}

FIELD_RE = re.compile(r"^//\s*([A-Za-z&/ ]+?):\s*(.*)$")
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
PLACEHOLDER_RE = re.compile(r"<[^<>]+>")  # unfilled template text like <Short descriptive title>
START, END = "<!-- CATALOGUE:START -->", "<!-- CATALOGUE:END -->"


def query_files() -> list[Path]:
    return sorted(p for folder in QUERY_FOLDERS for p in (REPO / folder).glob("*.kql"))


def parse_header(text: str) -> dict[str, str]:
    """Read the '// Field: value' comment block at the top of a query.

    Indented comment lines continue the previous field. Reading stops at the first
    line that isn't a comment, so comments further down the query are ignored.
    """
    fields: dict[str, str] = {}
    last = None
    for line in text.lstrip("﻿").splitlines():
        s = line.strip()
        if not s.startswith("//"):
            break
        if set(s) <= set("/=- "):  # banner lines like // ======
            last = None if s.strip("/ ") == "" else last
            continue
        m = FIELD_RE.match(s)
        is_field_line = m and len(s) - len(s[2:].lstrip()) <= 4  # "// Name:" not an indented continuation
        if is_field_line and m.group(1).strip() in KNOWN:
            last = m.group(1).strip()
            fields[last] = m.group(2).strip()
        elif is_field_line:
            last = None  # a field we don't track (e.g. "Reference:"): don't glue it onto the previous one
        elif last:
            fields[last] = (fields[last] + " " + s.lstrip("/").strip()).strip()
    return fields


def header_problems(fields: dict[str, str]) -> list[str]:
    if not fields:
        return ["no header block (copy the header template to the top of the file)"]
    problems = [f"missing '{k}'" for k in REQUIRED if not fields.get(k)]
    problems += [f"'{k}' still has template text {PLACEHOLDER_RE.search(v).group(0)}"
                 for k, v in fields.items() if PLACEHOLDER_RE.search(v)]
    if fields.get("Type") and fields["Type"] not in TYPES:
        problems.append(f"'Type' is '{fields['Type']}', expected one of: {', '.join(sorted(TYPES))}")
    if fields.get("MITRE ATT&CK") and not TECHNIQUE_RE.search(fields["MITRE ATT&CK"]):
        problems.append("'MITRE ATT&CK' has no technique IDs like T1059.001")
    if fields.get("Created") and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", fields["Created"]):
        problems.append("'Created' should be a date like 2026-11-17")
    return problems


# ---------------------------------------------------------------- headers command
def changed_queries(base: str) -> set[Path]:
    out = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--diff-filter=AMR", f"{base}...HEAD", "--", "*.kql"],
        cwd=REPO, check=True, capture_output=True, text=True,
    ).stdout
    return {(REPO / p).resolve() for p in out.split("\0") if p}


def annotate(level: str, path: Path, msg: str) -> None:
    rel = path.relative_to(REPO).as_posix()
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::{level} file={rel},line=1::{msg}")
    else:
        print(f"{level.upper():7} {rel}: {msg}")


def cmd_headers(base: str | None) -> int:
    changed = changed_queries(base) if base else {p.resolve() for p in query_files()}
    failed, warned, summary = 0, 0, []
    for path in query_files():
        problems = header_problems(parse_header(path.read_text(encoding="utf-8")))
        is_changed = path.resolve() in changed
        if problems:
            level = "error" if is_changed else "warning"
            annotate(level, path, "Header: " + "; ".join(problems))
            failed += is_changed
            warned += not is_changed
        icon = "✅" if not problems else ("❌" if is_changed else "⚠️")
        summary.append(f"| {icon} | `{path.relative_to(REPO).as_posix()}` | {'; '.join(problems) or 'OK'} |")

    report = (
        "## Query header check\n\n"
        f"{failed} changed quer{'y' if failed == 1 else 'ies'} failing, "
        f"{warned} older quer{'y' if warned == 1 else 'ies'} with warnings (not blocking).\n\n"
        "| | File | Result |\n|---|---|---|\n" + "\n".join(summary) + "\n"
    )
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(report)
    print(f"\nHeader check: {failed} failing, {warned} warning(s).")
    return 1 if failed else 0


# ---------------------------------------------------------------- build command
def collect() -> list[dict]:
    rows = []
    for path in query_files():
        fields = parse_header(path.read_text(encoding="utf-8"))
        rows.append({
            "folder": path.parent.name,
            "name": path.stem,
            "path": path.relative_to(REPO).as_posix(),
            "techniques": sorted(set(TECHNIQUE_RE.findall(fields.get("MITRE ATT&CK", "")))),
            "sources": fields.get("Data sources", ""),
        })
    return rows


def render_catalogue(rows: list[dict]) -> str:
    lines = [START, "<!-- Generated by .github/scripts/kql_catalogue.py - do not edit by hand. -->", ""]
    for folder in QUERY_FOLDERS:
        group = [r for r in rows if r["folder"] == folder]
        if not group:
            continue
        lines += [f"### {folder}", "", "| Query | MITRE ATT&CK | Data sources |", "|---|---|---|"]
        for r in group:
            link = r["path"].replace(" ", "%20")
            lines.append(f"| [{r['name']}]({link}) | {', '.join(r['techniques']) or '-'} | {r['sources'] or '-'} |")
        lines.append("")
    lines.append(END)
    return "\n".join(lines)


def render_layer(rows: list[dict]) -> str:
    by_tech: dict[str, list[str]] = {}
    for r in rows:
        for t in r["techniques"]:
            by_tech.setdefault(t, []).append(r["name"])
    layer = {
        "name": "hunting-grounds coverage",
        "description": "MITRE ATT&CK techniques covered by queries in xWhiff/hunting-grounds. "
                       "Score = number of queries. Generated from query headers.",
        "domain": "enterprise-attack",
        "versions": {"layer": "4.5"},
        "sorting": 3,
        "hideDisabled": False,
        "techniques": [
            {"techniqueID": t, "score": len(q), "comment": "; ".join(q), "showSubtechniques": True}
            for t, q in sorted(by_tech.items())
        ],
        "gradient": {"colors": ["#c6dbef", "#08519c"], "minValue": 0, "maxValue": max([3] + [len(q) for q in by_tech.values()])},
        "legendItems": [],
    }
    return json.dumps(layer, indent=2, ensure_ascii=False) + "\n"


def cmd_build(check: bool) -> int:
    rows = collect()
    readme = README.read_text(encoding="utf-8")
    if START not in readme or END not in readme:
        print(f"README.md needs the markers {START} and {END}.", file=sys.stderr)
        return 1
    new_readme = readme[: readme.index(START)] + render_catalogue(rows) + readme[readme.index(END) + len(END):]
    new_layer = render_layer(rows)
    old_layer = LAYER.read_text(encoding="utf-8") if LAYER.exists() else ""

    stale = [n for n, old, new in (("README.md", readme, new_readme), ("attack-coverage.json", old_layer, new_layer)) if old != new]
    if check:
        if stale:
            for n in stale:
                msg = (f"{n} is out of date. Run: python3 .github/scripts/kql_catalogue.py build "
                       "and commit the result.")
                print(f"::error file={n},line=1::{msg}" if os.environ.get("GITHUB_ACTIONS") else f"ERROR   {msg}")
            return 1
        print("Catalogue and ATT&CK layer are up to date.")
        return 0
    README.write_text(new_readme, encoding="utf-8")
    LAYER.write_text(new_layer, encoding="utf-8")
    techniques = sum(1 for _ in json.loads(new_layer)["techniques"])
    print(f"Wrote README.md catalogue ({len(rows)} queries) and attack-coverage.json ({techniques} techniques).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="regenerate the README catalogue and attack-coverage.json")
    b.add_argument("--check", action="store_true", help="don't write; fail if the files are out of date")
    h = sub.add_parser("headers", help="check query headers")
    h.add_argument("--base", help="git ref to diff against; only changed queries can fail (default: all queries fail)")
    args = ap.parse_args()
    return cmd_build(args.check) if args.cmd == "build" else cmd_headers(args.base)


if __name__ == "__main__":
    sys.exit(main())
