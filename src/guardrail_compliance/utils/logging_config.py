from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "WARNING") -> None:
    """Configure the guardrail_compliance logger.

    Call this once at CLI startup.  Library consumers who set up their own
    logging are not affected because we only configure the package-scoped
    logger, not the root logger.
    """
    numeric = getattr(logging, level.upper(), None)
    if not isinstance(numeric, int):
        numeric = logging.WARNING

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )

    logger = logging.getLogger("guardrail_compliance")
    logger.setLevel(numeric)
    if not logger.handlers:
        logger.addHandler(handler)
