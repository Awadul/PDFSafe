"""Structured logging setup (structlog over stdlib logging)."""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any
from uuid import uuid4

import structlog
from structlog.contextvars import bind_contextvars, clear_contextvars
from structlog.types import EventDict, Processor

from pdfsafe.config import Settings, get_settings

_CONFIGURED = False


def _add_service_context(settings: Settings) -> Processor:
    def processor(_: Any, __: str, event_dict: EventDict) -> EventDict:
        event_dict.setdefault("service", settings.app_name.lower())
        event_dict.setdefault("env", str(settings.env))
        return event_dict

    return processor


def _drop_color_message(_: Any, __: str, event_dict: EventDict) -> EventDict:
    event_dict.pop("color_message", None)
    return event_dict


def configure_logging(
    settings: Settings | None = None,
    *,
    force: bool = False,
    to_file: bool = False,
) -> None:
    """Configure structlog + stdlib logging once per process.

    Args:
        settings: Configuration; resolved from the cache when omitted.
        force: Reconfigure even if this process is already set up.
        to_file: Also write a rotating log under the user's log directory.
            The desktop build enables this because a frozen, windowed app has
            no console to print to.
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    settings = settings or get_settings()
    level = getattr(logging, settings.log_level)

    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        _drop_color_message,
        _add_service_context(settings),
    ]

    renderer: Processor = (
        structlog.processors.JSONRenderer()
        if settings.log_json
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    structlog.configure(
        processors=[
            *shared,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
    )

    handlers: list[logging.Handler] = []

    # A frozen windowed build has no stdout; guard against a None stream.
    if sys.stdout is not None:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        handlers.append(stream_handler)

    if to_file:
        file_handler = _build_file_handler(settings)
        if file_handler is not None:
            file_handler.setFormatter(
                structlog.stdlib.ProcessorFormatter(
                    foreign_pre_chain=shared,
                    processors=[
                        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                        structlog.processors.JSONRenderer(),
                    ],
                )
            )
            handlers.append(file_handler)

    if not handlers:  # pragma: no cover - no console and no writable log dir
        handlers.append(logging.NullHandler())

    root = logging.getLogger()
    root.handlers = handlers
    root.setLevel(level)

    for noisy in ("uvicorn.access", "botocore", "boto3", "s3transfer", "urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").propagate = True

    _CONFIGURED = True


def _build_file_handler(settings: Settings) -> logging.Handler | None:
    """Daily-rotating JSON log under the user's log directory."""
    from logging.handlers import TimedRotatingFileHandler

    from pdfsafe import paths

    try:
        target = paths.log_dir() / "pdfsafe.log"
        handler = TimedRotatingFileHandler(
            target,
            when="midnight",
            backupCount=max(1, settings.log_retention_days),
            encoding="utf-8",
            delay=True,
            utc=True,
        )
    except OSError:  # pragma: no cover - unwritable profile
        return None
    return handler


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger."""
    return structlog.stdlib.get_logger(name)


def new_request_context(**values: Any) -> str:
    """Bind a fresh correlation id (plus extras) to the logging context."""
    clear_contextvars()
    correlation_id = str(values.pop("correlation_id", None) or uuid4())
    bind_contextvars(correlation_id=correlation_id, **values)
    return correlation_id


def bind_context(**values: Any) -> None:
    bind_contextvars(**values)


def clear_context() -> None:
    clear_contextvars()


def redact(
    mapping: MutableMapping[str, Any], keys: tuple[str, ...] = ("api_key", "token")
) -> dict[str, Any]:
    """Return a copy of ``mapping`` with sensitive keys masked."""
    return {k: ("***" if k in keys else v) for k, v in mapping.items()}
