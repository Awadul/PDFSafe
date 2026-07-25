"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request, Security
from sqlalchemy.ext.asyncio import AsyncSession

from pdfsafe.api.security import (
    Principal,
    api_key_scheme,
    authenticate,
    client_identity,
    get_rate_limiter,
)
from pdfsafe.db.session import get_session

DBSession = Annotated[AsyncSession, Depends(get_session)]


async def current_principal(
    raw_key: Annotated[str | None, Security(api_key_scheme)] = None,
) -> Principal:
    """Resolve the caller from the ``X-API-Key`` header."""
    return authenticate(raw_key)


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]


async def enforce_rate_limit(request: Request, principal: CurrentPrincipal) -> None:
    """Apply the per-caller rate limit."""
    get_rate_limiter().check(client_identity(request, principal))


RateLimited = Depends(enforce_rate_limit)


def correlation_id(request: Request) -> str:
    """Correlation id assigned by the logging middleware."""
    return str(getattr(request.state, "correlation_id", ""))


CorrelationID = Annotated[str, Depends(correlation_id)]
