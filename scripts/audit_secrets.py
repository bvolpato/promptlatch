#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
from __future__ import annotations

import argparse
import hashlib
import os
import re
import runpy
import subprocess
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_PATTERN_MODULE = runpy.run_path(str(ROOT / "src" / "promptlatch" / "patterns.py"))
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (name, pattern)
    for name, pattern in _PATTERN_MODULE["BUILTIN_PATTERNS"]
    if name not in _PATTERN_MODULE["AUDIT_EXCLUDED_PATTERN_NAMES"]
]
SKIP_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "dist",
}
SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".whl",
}


@dataclass(frozen=True)
class Finding:
    scope: str
    source: str
    pattern: str
    line: int
    length: int
    value_hash: str


def run_git(args: list[str], *, input_bytes: bytes | None = None) -> bytes:
    return subprocess.check_output(
        ["git", *args],
        cwd=ROOT,
        input=input_bytes,
        stderr=subprocess.DEVNULL,
    )


def should_skip(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return True
    return path.suffix.lower() in SKIP_SUFFIXES


def line_number(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def scan_text(scope: str, source: str, text: str) -> Iterable[Finding]:
    for name, pattern in PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            yield Finding(
                scope=scope,
                source=source,
                pattern=name,
                line=line_number(text, match.start()),
                length=len(value),
                value_hash=hashlib.sha256(value.encode("utf-8")).hexdigest()[:16],
            )


def scan_worktree() -> list[Finding]:
    findings: list[Finding] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if should_skip(relative) or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_text("worktree", str(relative), text))
    return findings


def git_blob_objects() -> dict[str, str]:
    objects: dict[str, str] = {}
    output = run_git(["rev-list", "--objects", "--all"]).decode("utf-8", errors="replace")
    for line in output.splitlines():
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        object_id, path = parts
        objects.setdefault(object_id, path)
    return objects


def scan_git_history() -> list[Finding]:
    findings: list[Finding] = []
    for object_id, path in git_blob_objects().items():
        relative = Path(path)
        if should_skip(relative):
            continue
        try:
            object_type = run_git(["cat-file", "-t", object_id]).strip()
        except subprocess.CalledProcessError:
            continue
        if object_type != b"blob":
            continue
        try:
            data = run_git(["cat-file", "-p", object_id])
            text = data.decode("utf-8")
        except (UnicodeDecodeError, subprocess.CalledProcessError):
            continue
        findings.extend(scan_text("history", f"{object_id[:12]}:{path}", text))
    return findings


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("secret audit: clean")
        return

    by_pattern: dict[str, int] = defaultdict(int)
    for finding in findings:
        by_pattern[finding.pattern] += 1
    print("secret audit: findings")
    for pattern, count in sorted(by_pattern.items()):
        print(f"pattern={pattern} count={count}")
    print("locations:")
    for finding in findings:
        print(
            f"{finding.scope}\t{finding.source}:{finding.line}\t"
            f"pattern={finding.pattern}\tlength={finding.length}\tsha256={finding.value_hash}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan worktree and git history for secret patterns."
    )
    parser.add_argument("--history-only", action="store_true")
    parser.add_argument("--worktree-only", action="store_true")
    args = parser.parse_args()

    findings: list[Finding] = []
    if not args.history_only:
        findings.extend(scan_worktree())
    if not args.worktree_only:
        findings.extend(scan_git_history())
    print_findings(findings)
    if findings:
        raise SystemExit(1)


if __name__ == "__main__":
    os.chdir(ROOT)
    main()
