from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from promptlatch.config import AuditConfig
from promptlatch.redaction import RedactionStats

logger = logging.getLogger("promptlatch")


class AuditLogger:
    def __init__(self, config: AuditConfig):
        self.config = config

    def emit(self, event: str, **fields: Any) -> None:
        if not self.config.enabled:
            return
        payload = {"ts": datetime.now(UTC).isoformat(), "event": event, **fields}
        line = json.dumps(payload, sort_keys=True)
        if self.config.file:
            path = Path(self.config.file)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            return
        logger.info(line)

    def redaction(self, path: str, stats: RedactionStats) -> None:
        if stats.redactions:
            self.emit("redaction", path=path, redactions=stats.redactions, rules=stats.rule_hits)
