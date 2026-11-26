"""Compatibility imports for the previous package name."""

from __future__ import annotations

import warnings

warnings.warn(
    "promptcloak imports are deprecated; use promptlatch",
    FutureWarning,
    stacklevel=1,
)

from promptlatch import (  # noqa: E402
    PromptLatch,
    __version__,
    redact_messages,
    redact_params,
    redact_payload,
    redact_text,
    scan_messages,
    scan_params,
    scan_payload,
    scan_text,
)

PromptCloak = PromptLatch

__all__ = [
    "PromptCloak",
    "PromptLatch",
    "__version__",
    "redact_messages",
    "redact_params",
    "redact_payload",
    "redact_text",
    "scan_messages",
    "scan_params",
    "scan_payload",
    "scan_text",
]
