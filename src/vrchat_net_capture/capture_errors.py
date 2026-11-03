from __future__ import annotations

import logging
import sys
import traceback
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType


def configure_errors(capture_dir: Path) -> None:
    logger = logging.getLogger(__name__)
    logger.propagate = False
    for handler in logger.handlers:
        handler.close()
    logger.handlers.clear()
    if capture_dir.is_dir():
        logger.addHandler(logging.FileHandler(capture_dir / "postprocess-errors.log", encoding="utf-8", delay=True))
    else:
        logger.addHandler(logging.NullHandler())
    sys.excepthook = report_error


def report_error(exception_type: type[BaseException], error: BaseException, trace: TracebackType | None) -> None:
    logging.getLogger(__name__).critical("%s", error, exc_info=(exception_type, error, trace))
    sys.stderr.write("".join(traceback.format_exception_only(exception_type, error)))
