"""Application logs deliberately exclude bodies, paths, headers and exception text."""

import json
import logging
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    def format(self, record):
        allowed = {"scan_id", "source", "stage", "status", "error_type", "count", "delivery_id"}
        fields = getattr(record, "fields", {})
        return json.dumps(
            {
                "time": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "event": record.getMessage(),
                **{key: value for key, value in fields.items() if key in allowed},
            },
            ensure_ascii=False,
        )


logger = logging.getLogger("vulnradar")


def configure_logging():
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
