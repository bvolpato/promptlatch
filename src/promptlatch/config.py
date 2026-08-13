from __future__ import annotations

import os
import re
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from promptlatch.security import decrypt_text, load_key

CONFIG_DIR = Path.home() / ".config" / "promptlatch"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "config.yaml"
DEFAULT_KEY_PATH = CONFIG_DIR / "key"
LEGACY_CONFIG_DIR = Path.home() / ".config" / "promptcloak"
LEGACY_CONFIG_PATH = LEGACY_CONFIG_DIR / "config.yaml"
LEGACY_KEY_PATH = LEGACY_CONFIG_DIR / "key"


class ServerConfig(BaseModel):
    host: str = Field(default="127.0.0.1", min_length=1)
    port: int = Field(default=8000, ge=1, le=65535)
    api_key: str | None = None
    require_api_key: bool = False
    debug_requests: bool = False
    debug_max_body_chars: int = Field(default=20000, ge=0)
    max_request_body_bytes: int = Field(default=32 * 1024 * 1024, ge=1024)

    @model_validator(mode="after")
    def validate_required_api_key(self) -> ServerConfig:
        if self.require_api_key and not self.api_key:
            raise ValueError("server API key is required but missing")
        return self


class TargetConfig(BaseModel):
    default_base_url: str = "https://api.openai.com/v1"
    api_key: str | None = None
    api_key_header: Literal["authorization", "x-api-key"] = "authorization"
    forward_client_authorization: bool = False
    timeout_seconds: float = Field(default=180.0, gt=0)
    allowed_base_urls: list[str] = Field(default_factory=list)
    block_private_targets: bool = True

    @field_validator("default_base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return _validated_base_url(value)

    @field_validator("allowed_base_urls")
    @classmethod
    def validate_allowed_base_urls(cls, values: list[str]) -> list[str]:
        return [_validated_base_url(value) for value in values]


class RuleConfig(BaseModel):
    type: Literal["exact", "regex"]
    value: str
    name: str | None = None

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str, info: Any) -> str:
        if not value:
            raise ValueError("redaction rule cannot be empty")
        if info.data.get("type") == "exact" and len(value) < 8:
            raise ValueError("exact redaction rules require at least 8 characters")
        if info.data.get("type") == "regex":
            try:
                pattern = re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid redaction regex: {exc}") from exc
            if pattern.search("") is not None:
                raise ValueError("redaction regex cannot match empty text")
        return value

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value):
            raise ValueError("redaction rule name must be 1-64 safe characters")
        return value


def _validated_base_url(value: str) -> str:
    value = value.rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target base URL must use http:// or https:// with a hostname")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("target base URL cannot contain userinfo, query, or fragment")
    try:
        _ = parsed.port
    except ValueError:
        raise ValueError("target base URL has invalid port") from None
    return value


class RedactionConfig(BaseModel):
    enabled: bool = True
    engine: Literal["detect-secrets", "basic"] = "detect-secrets"
    redact_mode: Literal["partial", "full"] = "full"
    placeholder: str = "[REDACTED_SECRET]"
    rules: list[RuleConfig] = Field(default_factory=list)
    encrypted: bool = False
    encrypted_rules: str | None = None
    max_extra_rules: int = Field(default=20, ge=0, le=100)
    max_extra_rule_chars: int = Field(default=1024, ge=8, le=8192)
    max_extra_rules_header_bytes: int = Field(default=16384, ge=256, le=65536)
    allow_extra_regex_rules: bool = False

    @model_validator(mode="after")
    def validate_encrypted_rules(self) -> RedactionConfig:
        if self.encrypted:
            if not self.encrypted_rules:
                raise ValueError("encrypted redaction requires encrypted_rules")
        elif self.encrypted_rules:
            raise ValueError("encrypted_rules requires encrypted: true")
        return self


class AuditConfig(BaseModel):
    enabled: bool = True
    file: Path | None = None


class CompatConfig(BaseModel):
    responses_to_chat: bool = False


class Settings(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    target: TargetConfig = Field(default_factory=TargetConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    compat: CompatConfig = Field(default_factory=CompatConfig)

    @model_validator(mode="after")
    def validate_auth_forwarding(self) -> Settings:
        if self.server.api_key and self.target.forward_client_authorization:
            raise ValueError(
                "proxy authentication cannot be combined with client authorization forwarding"
            )
        return self


def _deep_update(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_update(base[key], value)
        else:
            base[key] = value
    return base


def _env_overrides() -> dict[str, Any]:
    mapping: dict[str, tuple[str, ...]] = {
        "PROMPTLATCH_HOST": ("server", "host"),
        "PROMPTLATCH_PORT": ("server", "port"),
        "PROMPTLATCH_SERVER_API_KEY": ("server", "api_key"),
        "PROMPTLATCH_REQUIRE_SERVER_API_KEY": ("server", "require_api_key"),
        "PROMPTLATCH_DEBUG_REQUESTS": ("server", "debug_requests"),
        "PROMPTLATCH_DEBUG_MAX_BODY_CHARS": ("server", "debug_max_body_chars"),
        "PROMPTLATCH_MAX_REQUEST_BODY_BYTES": ("server", "max_request_body_bytes"),
        "PROMPTLATCH_TARGET_DEFAULT_BASE_URL": ("target", "default_base_url"),
        "PROMPTLATCH_TARGET_BASE_URL": ("target", "default_base_url"),
        "PROMPTLATCH_TARGET_API_KEY": ("target", "api_key"),
        "PROMPTLATCH_TARGET_API_KEY_HEADER": ("target", "api_key_header"),
        "PROMPTLATCH_FORWARD_CLIENT_AUTHORIZATION": (
            "target",
            "forward_client_authorization",
        ),
        "PROMPTLATCH_TARGET_TIMEOUT_SECONDS": ("target", "timeout_seconds"),
        "PROMPTLATCH_REDACTION_ENABLED": ("redaction", "enabled"),
        "PROMPTLATCH_REDACTION_ENGINE": ("redaction", "engine"),
        "PROMPTLATCH_REDACTION_MODE": ("redaction", "redact_mode"),
        "PROMPTLATCH_MAX_EXTRA_RULES": ("redaction", "max_extra_rules"),
        "PROMPTLATCH_MAX_EXTRA_RULE_CHARS": ("redaction", "max_extra_rule_chars"),
        "PROMPTLATCH_MAX_EXTRA_RULES_HEADER_BYTES": (
            "redaction",
            "max_extra_rules_header_bytes",
        ),
        "PROMPTLATCH_ALLOW_EXTRA_REGEX_RULES": ("redaction", "allow_extra_regex_rules"),
        "PROMPTLATCH_RESPONSES_TO_CHAT": ("compat", "responses_to_chat"),
    }
    data: dict[str, Any] = {}
    for env_name, path in mapping.items():
        legacy_name = env_name.replace("PROMPTLATCH_", "PROMPTCLOAK_", 1)
        selected_name = env_name if env_name in os.environ else legacy_name
        if selected_name not in os.environ:
            continue
        if selected_name == legacy_name:
            warnings.warn(
                f"{legacy_name} is deprecated; use {env_name}",
                FutureWarning,
                stacklevel=2,
            )
        target = data
        for segment in path[:-1]:
            target = target.setdefault(segment, {})
        raw: str = os.environ[selected_name]
        if raw.lower() in {"true", "false"}:
            value: Any = raw.lower() == "true"
        elif raw.isdigit():
            value = int(raw)
        else:
            try:
                value = float(raw)
            except ValueError:
                value = raw
        target[path[-1]] = value
    return data


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ValueError("PromptLatch config root must be a mapping")
    return loaded


def _decrypt_rules_if_needed(settings: Settings, key_path: Path) -> Settings:
    redaction = settings.redaction
    if not redaction.encrypted or not redaction.encrypted_rules:
        return settings
    key = load_key(key_path)
    decrypted = decrypt_text(redaction.encrypted_rules, key)
    rules = yaml.safe_load(decrypted) or []
    redaction.rules = [RuleConfig.model_validate(rule) for rule in rules]
    return settings


def _resolved_path(
    explicit: Path | None,
    env_name: str,
    legacy_env_name: str,
    default: Path,
    legacy_default: Path,
) -> Path:
    if explicit is not None:
        selected = explicit
    elif env_name in os.environ:
        return Path(os.environ[env_name])
    elif legacy_env_name in os.environ:
        warnings.warn(
            f"{legacy_env_name} is deprecated; use {env_name}",
            FutureWarning,
            stacklevel=2,
        )
        return Path(os.environ[legacy_env_name])
    else:
        selected = default

    if selected == default and not default.exists() and legacy_default.exists():
        warnings.warn(
            f"using legacy path {legacy_default}; move it to {default}",
            FutureWarning,
            stacklevel=2,
        )
        return legacy_default
    return selected


def load_settings(config_path: Path | None = None, key_path: Path | None = None) -> Settings:
    path = _resolved_path(
        config_path,
        "PROMPTLATCH_CONFIG",
        "PROMPTCLOAK_CONFIG",
        DEFAULT_CONFIG_PATH,
        LEGACY_CONFIG_PATH,
    )
    key_file = _resolved_path(
        key_path,
        "PROMPTLATCH_KEY_FILE",
        "PROMPTCLOAK_KEY_FILE",
        DEFAULT_KEY_PATH,
        LEGACY_KEY_PATH,
    )
    data = _deep_update(_load_yaml(path), _env_overrides())
    settings = Settings.model_validate(data)
    return _decrypt_rules_if_needed(settings, key_file)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()


def config_template(target_base_url: str, target_api_key_env: str) -> str:
    return yaml.safe_dump(
        {
            "server": {
                "host": "127.0.0.1",
                "port": 8000,
                "api_key": None,
                "require_api_key": False,
                "debug_requests": False,
                "debug_max_body_chars": 20000,
                "max_request_body_bytes": 33554432,
            },
            "target": {
                "default_base_url": target_base_url,
                "api_key": f"${{{target_api_key_env}}}",
                "api_key_header": "authorization",
                "forward_client_authorization": False,
                "timeout_seconds": 180,
                "allowed_base_urls": [],
                "block_private_targets": True,
            },
            "redaction": {
                "enabled": True,
                "engine": "detect-secrets",
                "redact_mode": "full",
                "encrypted": False,
                "max_extra_rules": 20,
                "max_extra_rule_chars": 1024,
                "max_extra_rules_header_bytes": 16384,
                "allow_extra_regex_rules": False,
                "rules": [],
            },
            "audit": {"enabled": True, "file": None},
            "compat": {"responses_to_chat": False},
        },
        sort_keys=False,
    )


def expand_env_values(data: Any) -> Any:
    if isinstance(data, dict):
        return {key: expand_env_values(value) for key, value in data.items()}
    if isinstance(data, list):
        return [expand_env_values(value) for value in data]
    if isinstance(data, str) and data.startswith("${") and data.endswith("}"):
        return os.getenv(data[2:-1])
    return data
