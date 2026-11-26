"""PromptLatch package."""

import logging as _logging
import warnings as _warnings

_showwarning = _warnings.showwarning

from promptlatch.library import (  # noqa: E402
    PromptLatch,
    redact_messages,
    redact_params,
    redact_payload,
    redact_text,
    scan_messages,
    scan_params,
    scan_payload,
    scan_text,
)
from promptlatch.version import __version__  # noqa: E402

# Importing detect-secrets sends all Python warnings to logging, which hides warnings
# from the host process and our migration warnings. Undo only that redirect.
if _warnings.showwarning is not _showwarning:
    _logging.captureWarnings(False)

__all__ = [
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
