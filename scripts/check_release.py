#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
from __future__ import annotations

import argparse
import os
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
TAG = re.compile(r"^v(?P<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


def read_pyproject_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def read_package_version() -> str:
    text = (ROOT / "src" / "promptlatch" / "version.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', text, re.MULTILINE)
    if not match:
        raise ValueError("src/promptlatch/version.py missing __version__")
    return match.group(1)


def read_chart_value(name: str) -> str:
    text = (ROOT / "charts" / "promptlatch" / "Chart.yaml").read_text(encoding="utf-8")
    match = re.search(rf"^{name}:\s*\"?([^\"\n]+)\"?$", text, re.MULTILINE)
    if not match:
        raise ValueError(f"charts/promptlatch/Chart.yaml missing {name}")
    return match.group(1)


def read_values_image_tag() -> str:
    text = (ROOT / "charts" / "promptlatch" / "values.yaml").read_text(encoding="utf-8")
    match = re.search(r'^\s+tag:\s*"?([^"\n]+)"?$', text, re.MULTILINE)
    if not match:
        raise ValueError("charts/promptlatch/values.yaml missing image tag")
    return match.group(1)


def read_lock_version() -> str:
    data = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    for package in data.get("package", []):
        if package.get("name") == "promptlatch":
            return str(package["version"])
    raise ValueError("uv.lock missing promptlatch package")


def required_release_references(version: str) -> dict[str, tuple[Path, str]]:
    wheel = f"releases/download/v{version}/promptlatch-{version}-py3-none-any.whl"
    chart = f"releases/download/v{version}/promptlatch-{version}.tgz"
    image = f"ghcr.io/bvolpato/promptlatch:{version}"
    return {
        "README wheel": (ROOT / "README.md", wheel),
        "README Helm chart": (ROOT / "README.md", chart),
        "README container": (ROOT / "README.md", image),
        "PROMPT wheel": (ROOT / "PROMPT.md", wheel),
        "PROMPT container": (ROOT / "PROMPT.md", image),
        "site wheel": (ROOT / "site" / "index.html", wheel),
        "site Helm chart": (ROOT / "site" / "index.html", chart),
        "site container": (ROOT / "site" / "index.html", image),
    }


def tag_version(tag: str | None) -> str | None:
    if not tag:
        return None
    match = TAG.fullmatch(tag)
    if not match:
        raise ValueError(f"release tag must look like v0.1.0, got {tag!r}")
    return match.group("version")


def github_tag() -> str | None:
    if os.getenv("GITHUB_REF_TYPE") != "tag":
        return None
    return os.getenv("GITHUB_REF_NAME")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate release version metadata.")
    parser.add_argument("--tag", default=github_tag())
    args = parser.parse_args()

    expected = tag_version(args.tag) or read_pyproject_version()
    versions = {
        "pyproject.toml": read_pyproject_version(),
        "src/promptlatch/version.py": read_package_version(),
        "charts/promptlatch/Chart.yaml version": read_chart_value("version"),
        "charts/promptlatch/Chart.yaml appVersion": read_chart_value("appVersion"),
        "charts/promptlatch/values.yaml image tag": read_values_image_tag(),
        "uv.lock": read_lock_version(),
    }

    if not SEMVER.fullmatch(expected):
        raise SystemExit(f"invalid version: {expected}")

    mismatches = [
        f"{source}={version}" for source, version in versions.items() if version != expected
    ]
    if mismatches:
        raise SystemExit("release version mismatch: " + ", ".join(mismatches))

    missing_references = [
        name
        for name, (path, value) in required_release_references(expected).items()
        if value not in path.read_text(encoding="utf-8")
    ]
    if missing_references:
        raise SystemExit("release references missing: " + ", ".join(missing_references))

    print(f"release check: {expected}")


if __name__ == "__main__":
    main()
