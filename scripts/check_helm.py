#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pyyaml==6.0.3",
# ]
# ///
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts" / "promptlatch"


def render(release_name: str = "promptlatch", *args: str) -> list[dict[str, Any]]:
    result = subprocess.run(
        ["helm", "template", release_name, str(CHART), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return [item for item in yaml.safe_load_all(result.stdout) if isinstance(item, dict)]


def deployment(documents: list[dict[str, Any]]) -> dict[str, Any]:
    return next(item for item in documents if item.get("kind") == "Deployment")


def assert_server_auth_secret(document: dict[str, Any], expected_name: str) -> None:
    container = document["spec"]["template"]["spec"]["containers"][0]
    auth = next(item for item in container["env"] if item["name"] == "PROMPTLATCH_SERVER_API_KEY")
    actual_name = auth["valueFrom"]["secretKeyRef"]["name"]
    if actual_name != expected_name:
        raise SystemExit(f"server auth references {actual_name!r}, expected {expected_name!r}")


def container_env(document: dict[str, Any]) -> list[dict[str, Any]]:
    return document["spec"]["template"]["spec"]["containers"][0]["env"]


def main() -> None:
    default_documents = render()
    default_deployment = deployment(default_documents)
    assert_server_auth_secret(default_deployment, "promptlatch-secret")
    if not any(
        item == {"name": "PROMPTLATCH_REQUIRE_SERVER_API_KEY", "value": "true"}
        for item in container_env(default_deployment)
    ):
        raise SystemExit("default chart does not require configured proxy authentication")
    if not any(item.get("kind") == "Secret" for item in default_documents):
        raise SystemExit("default chart did not render managed Secret")

    external_documents = render("promptlatch", "--set", "existingSecret=promptlatch-env")
    external_deployment = deployment(external_documents)
    container = external_deployment["spec"]["template"]["spec"]["containers"][0]
    if container.get("envFrom") != [{"secretRef": {"name": "promptlatch-env"}}]:
        raise SystemExit("existing Secret is not loaded through envFrom")
    if any(item["name"] == "PROMPTLATCH_SERVER_API_KEY" for item in container["env"]):
        raise SystemExit("existing Secret auth key is not loaded through envFrom")
    if any(item.get("kind") == "Secret" for item in external_documents):
        raise SystemExit("chart rendered managed Secret with existingSecret configured")

    for release_name, fullname in {
        "promptcloak": "promptcloak",
        "team-proxy": "team-proxy-promptcloak",
    }.items():
        legacy_documents = render(
            release_name,
            "--set",
            "migration.preserveLegacyNames=true",
        )
        legacy_deployment = deployment(legacy_documents)
        if legacy_deployment["metadata"]["name"] != fullname:
            raise SystemExit(f"legacy release Deployment changed for {release_name}")
        selector = legacy_deployment["spec"]["selector"]["matchLabels"]
        if selector != {"app.kubernetes.io/name": "promptcloak"}:
            raise SystemExit(f"legacy release selector changed for {release_name}")
        legacy_names = {
            item["kind"]: item["metadata"]["name"]
            for item in legacy_documents
            if item.get("kind") in {"Secret", "Service"}
        }
        expected = {"Secret": f"{fullname}-secret", "Service": fullname}
        if legacy_names != expected:
            raise SystemExit(f"legacy release resources changed: {legacy_names}")

    print("helm check: auth modes and legacy upgrade identity valid")


if __name__ == "__main__":
    main()
