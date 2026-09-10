#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pyyaml==6.0.3",
# ]
# ///
from __future__ import annotations

import shutil
import subprocess
import tempfile
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


def service(documents: list[dict[str, Any]]) -> dict[str, Any]:
    return next(item for item in documents if item.get("kind") == "Service")


def selector_matches(selector: dict[str, str], labels: dict[str, str]) -> bool:
    return all(labels.get(key) == value for key, value in selector.items())


def assert_existing_selector_preserved() -> None:
    expected_selector = {
        "matchLabels": {
            "app.kubernetes.io/name": "promptcloak",
            "legacy.example/selector": "kept",
        },
        "matchExpressions": [
            {
                "key": "legacy.example/tier",
                "operator": "In",
                "values": ["api", "worker"],
            }
        ],
    }
    harness = """\
{{- $matchLabels := dict "app.kubernetes.io/name" "promptcloak" -}}
{{- $_ := set $matchLabels "legacy.example/selector" "kept" -}}
{{- $matchExpression := dict "key" "legacy.example/tier" "operator" "In" -}}
{{- $_ := set $matchExpression "values" (list "api" "worker") -}}
{{- $existingSelector := dict "matchLabels" $matchLabels -}}
{{- $_ := set $existingSelector "matchExpressions" (list $matchExpression) -}}
{{- $selectorContext := dict "root" . "existingSelector" $existingSelector -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: selector-harness
data:
  selector: |
{{ include "promptlatch.deploymentSelector" $selectorContext | nindent 4 }}
"""
    with tempfile.TemporaryDirectory() as temp_dir:
        chart = Path(temp_dir) / "promptlatch"
        shutil.copytree(CHART, chart)
        (chart / "templates" / "selector-harness.yaml").write_text(harness, encoding="utf-8")
        result = subprocess.run(
            [
                "helm",
                "template",
                "selector-harness",
                str(chart),
                "--show-only",
                "templates/selector-harness.yaml",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    document = next(item for item in yaml.safe_load_all(result.stdout) if isinstance(item, dict))
    actual_selector = yaml.safe_load(document["data"]["selector"])
    if actual_selector != expected_selector:
        raise SystemExit(
            f"existing Deployment selector changed: {actual_selector}, expected {expected_selector}"
        )


def assert_server_auth_secret(document: dict[str, Any], expected_name: str) -> None:
    container = document["spec"]["template"]["spec"]["containers"][0]
    auth = next(item for item in container["env"] if item["name"] == "PROMPTLATCH_SERVER_API_KEY")
    actual_name = auth["valueFrom"]["secretKeyRef"]["name"]
    if actual_name != expected_name:
        raise SystemExit(f"server auth references {actual_name!r}, expected {expected_name!r}")


def container_env(document: dict[str, Any]) -> list[dict[str, Any]]:
    return document["spec"]["template"]["spec"]["containers"][0]["env"]


def main() -> None:
    assert_existing_selector_preserved()

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

    release_documents = {
        release_name: render(release_name) for release_name in ("team-a", "team-b")
    }
    for release_name, documents in release_documents.items():
        release_deployment = deployment(documents)
        expected_selector = {
            "app.kubernetes.io/name": "promptlatch",
            "app.kubernetes.io/instance": release_name,
        }
        actual_selector = release_deployment["spec"]["selector"]["matchLabels"]
        if actual_selector != expected_selector:
            raise SystemExit(
                f"fresh release {release_name} selector is {actual_selector}, "
                f"expected {expected_selector}"
            )
        pod_labels = release_deployment["spec"]["template"]["metadata"]["labels"]
        if not selector_matches(expected_selector, pod_labels):
            raise SystemExit(f"fresh release {release_name} pod labels omit release identity")
        service_selector = service(documents)["spec"]["selector"]
        if service_selector != expected_selector:
            raise SystemExit(
                f"fresh release {release_name} Service selector is {service_selector}, "
                f"expected {expected_selector}"
            )

    for release_name, documents in release_documents.items():
        other_release = next(name for name in release_documents if name != release_name)
        selector = service(documents)["spec"]["selector"]
        other_pod_labels = deployment(release_documents[other_release])["spec"]["template"][
            "metadata"
        ]["labels"]
        if selector_matches(selector, other_pod_labels):
            raise SystemExit(f"release {release_name} Service selects {other_release} pods")

    upgrade_documents = render("promptlatch", "--is-upgrade")
    upgrade_deployment = deployment(upgrade_documents)
    upgrade_selector = upgrade_deployment["spec"]["selector"]["matchLabels"]
    expected_upgrade_service_selector = {
        "app.kubernetes.io/name": "promptlatch",
        "app.kubernetes.io/instance": "promptlatch",
    }
    if upgrade_selector != expected_upgrade_service_selector:
        raise SystemExit(f"offline fixed-release selector changed: {upgrade_selector}")
    upgrade_pod_labels = upgrade_deployment["spec"]["template"]["metadata"]["labels"]
    if not selector_matches(expected_upgrade_service_selector, upgrade_pod_labels):
        raise SystemExit("upgrade pod labels omit release identity")
    if service(upgrade_documents)["spec"]["selector"] != expected_upgrade_service_selector:
        raise SystemExit("upgrade Service selector is not isolated")

    migration_documents = render(
        "promptlatch",
        "--is-upgrade",
        "--set",
        "migration.preserveSelector=true",
    )
    migration_selector = deployment(migration_documents)["spec"]["selector"]["matchLabels"]
    if migration_selector != {"app.kubernetes.io/name": "promptlatch"}:
        raise SystemExit(f"explicit migration selector changed: {migration_selector}")

    for release_name, fullname in {
        "promptcloak": "promptcloak",
        "team-proxy": "team-proxy-promptcloak",
    }.items():
        legacy_documents = render(
            release_name,
            "--is-upgrade",
            "--set",
            "migration.preserveLegacyNames=true",
        )
        legacy_deployment = deployment(legacy_documents)
        if legacy_deployment["metadata"]["name"] != fullname:
            raise SystemExit(f"legacy release Deployment changed for {release_name}")
        selector = legacy_deployment["spec"]["selector"]["matchLabels"]
        if selector != {"app.kubernetes.io/name": "promptcloak"}:
            raise SystemExit(f"legacy release selector changed for {release_name}")
        pod_labels = legacy_deployment["spec"]["template"]["metadata"]["labels"]
        expected_service_selector = {
            "app.kubernetes.io/name": "promptcloak",
            "app.kubernetes.io/instance": release_name,
        }
        if not selector_matches(expected_service_selector, pod_labels):
            raise SystemExit(f"legacy release {release_name} pod labels omit release identity")
        if service(legacy_documents)["spec"]["selector"] != expected_service_selector:
            raise SystemExit(f"legacy release {release_name} Service selector is not isolated")
        legacy_names = {
            item["kind"]: item["metadata"]["name"]
            for item in legacy_documents
            if item.get("kind") in {"Secret", "Service"}
        }
        expected = {"Secret": f"{fullname}-secret", "Service": fullname}
        if legacy_names != expected:
            raise SystemExit(f"legacy release resources changed: {legacy_names}")

    print("helm check: auth modes, release routing, and legacy upgrade identity valid")


if __name__ == "__main__":
    main()
