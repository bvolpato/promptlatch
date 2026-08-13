from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
import yaml

from promptlatch.config import DEFAULT_CONFIG_PATH, DEFAULT_KEY_PATH, config_template, load_settings
from promptlatch.proxy import create_app
from promptlatch.redaction import SecretRedactor
from promptlatch.security import encrypt_text, load_key, write_key_file, write_private_text
from promptlatch.version import __version__

app = typer.Typer(help="PromptLatch local secret-redacting LLM proxy.")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Run PromptLatch."""


@app.command()
def serve(
    config: Annotated[Path, typer.Option(help="Config file path.")] = DEFAULT_CONFIG_PATH,
    host: Annotated[str | None, typer.Option(help="Override bind host.")] = None,
    port: Annotated[int | None, typer.Option(help="Override bind port.")] = None,
    debug_requests: Annotated[
        bool,
        typer.Option(
            "--debug-requests",
            help=(
                "Emergency local tracing. Logs raw request bodies before redaction; "
                "secrets may be printed."
            ),
        ),
    ] = False,
) -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("promptlatch").setLevel(logging.INFO)
    settings = load_settings(config)
    if host:
        settings.server.host = host
    if port:
        settings.server.port = port
    if debug_requests:
        settings.server.debug_requests = True
    uvicorn.run(create_app(settings), host=settings.server.host, port=settings.server.port)


@app.command()
def version() -> None:
    typer.echo(__version__)


@app.command()
def init(
    config: Annotated[Path, typer.Option(help="Config file to create.")] = DEFAULT_CONFIG_PATH,
    target_base_url: Annotated[
        str,
        typer.Option(help="Default upstream base URL."),
    ] = "https://api.openai.com/v1",
    target_api_key_env: Annotated[
        str,
        typer.Option(help="Environment variable holding upstream API key."),
    ] = "OPENAI_API_KEY",
    force: Annotated[bool, typer.Option(help="Overwrite existing config.")] = False,
) -> None:
    if config.exists() and not force:
        raise typer.BadParameter(f"{config} already exists")
    write_private_text(config, config_template(target_base_url, target_api_key_env))
    typer.echo(f"created {config}")


@app.command("encrypt-rules")
def encrypt_rules(
    config: Annotated[Path, typer.Option(help="Config file to update.")] = DEFAULT_CONFIG_PATH,
    key_file: Annotated[Path, typer.Option(help="AES-GCM key file.")] = DEFAULT_KEY_PATH,
) -> None:
    data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    redaction = data.setdefault("redaction", {})
    rules = redaction.get("rules", [])
    if redaction.get("encrypted_rules"):
        if rules:
            raise typer.BadParameter("config contains both plain and encrypted redaction rules")
        typer.echo(f"redaction rules already encrypted in {config}")
        return
    if not key_file.exists():
        write_key_file(key_file)
    encrypted = encrypt_text(yaml.safe_dump(rules, sort_keys=False), load_key(key_file))
    redaction["encrypted"] = True
    redaction["encrypted_rules"] = encrypted
    redaction["rules"] = []
    write_private_text(config, yaml.safe_dump(data, sort_keys=False))
    typer.echo(f"encrypted redaction rules in {config}")
    typer.echo(f"key file {key_file}")


@app.command()
def scan(
    text: Annotated[str, typer.Argument(help="Text to scan and redact.")],
    config: Annotated[Path, typer.Option(help="Config file path.")] = DEFAULT_CONFIG_PATH,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    redactor = SecretRedactor(load_settings(config).redaction)
    result = redactor.redact_text(text)
    if json_output:
        typer.echo(
            json.dumps({"text": result.value, "stats": result.stats.__dict__}, sort_keys=True)
        )
    else:
        typer.echo(result.value)


@app.command()
def doctor(
    config: Annotated[Path, typer.Option(help="Config file path.")] = DEFAULT_CONFIG_PATH,
) -> None:
    settings = load_settings(config)
    checks = {
        "config": str(config),
        "config_exists": config.exists(),
        "target": settings.target.default_base_url,
        "redaction": settings.redaction.enabled,
        "engine": settings.redaction.engine,
        "responses_to_chat": settings.compat.responses_to_chat,
        "telemetry": False,
    }
    typer.echo(json.dumps(checks, indent=2, sort_keys=True))
