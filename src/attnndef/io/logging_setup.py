"""Structured (JSON-line) logging, separate from the evidence sink.

Evidence (sink.py) is *what happened, as structured facts* for later
querying. Logging here is *operational trace* (what the program was
doing, warnings, stack traces) -- keep the two separate so evidence stays
clean and machine-parseable.
"""
from __future__ import annotations

import json
import logging
import sys
import time


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": record.created,
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(extra)
        return json.dumps(payload, separators=(",", ":"))


def setup_logging(level: int = logging.INFO, stream=None) -> logging.Logger:
    logger = logging.getLogger("attnndef")
    logger.setLevel(level)
    logger.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def log_with_fields(logger: logging.Logger, level: int, msg: str, **fields) -> None:
    logger.log(level, msg, extra={"extra_fields": fields})
