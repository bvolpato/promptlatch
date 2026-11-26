#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Export built-in redaction patterns to site/rules.js for the homepage demo."""

from __future__ import annotations

import argparse
import json
import re
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "site" / "rules.js"
# Python-only syntax that has no equivalent in the JavaScript engines the site supports.
UNSUPPORTED = re.compile(r"\(\?>|[*+?}]\+|\\[AZz]|\(\?[aiLmsux-]+[:)]")


def to_javascript(pattern: re.Pattern[str]) -> tuple[str, str]:
    source = pattern.pattern
    flags = "g"
    if pattern.flags & re.IGNORECASE:
        source = source.removeprefix("(?i)")
        flags += "i"
    elif "(?i:" in source:
        # Scoped flags are not portable. The affected pattern has no case-sensitive part.
        source = source.replace("(?i:", "(?:")
        flags += "i"
    source = source.replace("(?P<", "(?<")
    source = re.sub(r"\(\?P=(\w+)\)", r"\\k<\1>", source)
    if UNSUPPORTED.search(source):
        raise ValueError(f"pattern needs a JavaScript translation: {source}")
    return source, flags


def render() -> str:
    patterns = runpy.run_path(str(ROOT / "src" / "promptlatch" / "patterns.py"))["BUILTIN_PATTERNS"]
    rows = [[name, *to_javascript(pattern)] for name, pattern in patterns]
    # Escape PEM-style headers so the secret audit does not match the pattern source.
    body = ",\n".join(f"  {json.dumps(row)}" for row in rows)
    body = body.replace("-----BEGIN", r"\u002d----BEGIN")
    return (
        "// Generated from src/promptlatch/patterns.py. Run `uv run scripts/build_site_rules.py`.\n"
        f"globalThis.PROMPTLATCH_RULES = [\n{body},\n];\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if site/rules.js is stale")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != expected:
            raise SystemExit("site/rules.js is stale: run `uv run scripts/build_site_rules.py`")
        print("site rules: current")
        return
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"site rules: wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
