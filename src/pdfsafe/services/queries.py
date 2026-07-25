"""Read-side queries for the API and dashboard."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pdfsafe.db.models import AIAssessment, Scan
from pdfsafe.enums import ScanStatus, Verdict
from pdfsafe.exceptions import ScanNotFoundError
from pdfsafe.schemas.scan import ScanFilter, ScanStats


async def get_scan(session: AsyncSession, scan_id: uuid.UUID, *, detail: bool = True) -> Scan:
    """Fetch one scan, eagerly loading its children when ``detail`` is set."""
    statement: Select[tuple[Scan]] = select(Scan).where(Scan.id == scan_id)
    if detail:
        statement = statement.options(
            selectinload(Scan.indicators),
            selectinload(Scan.ai_assessments),
            selectinload(Scan.report),
        )
    scan = (await session.execute(statement)).scalar_one_or_none()
    if scan is None:
        raise ScanNotFoundError(f"Scan {scan_id} does not exist", scan_id=str(scan_id))
    return scan


async def list_scans(session: AsyncSession, filters: ScanFilter) -> tuple[list[Scan], int]:
    """Return a page of scans plus the total row count for the same filters."""
    statement = select(Scan)
    statement = _apply_filters(statement, filters)

    count_statement = select(func.count()).select_from(_apply_filters(select(Scan), filters).subquery())
    total = int((await session.execute(count_statement)).scalar_one())

    order_column = Scan.risk_score if filters.order_by == "risk_score" else Scan.created_at
    ordering = order_column.asc() if filters.order_dir == "asc" else order_column.desc()

    statement = statement.order_by(ordering, Scan.id).limit(filters.limit).offset(filters.offset)
    rows = list((await session.execute(statement)).scalars().all())
    return rows, total


def _apply_filters(statement: Select[tuple[Scan]], filters: ScanFilter) -> Select[tuple[Scan]]:
    if filters.status is not None:
        statement = statement.where(Scan.status == filters.status)
    if filters.verdict is not None:
        statement = statement.where(Scan.verdict == filters.verdict)
    if filters.sha256:
        statement = statement.where(Scan.sha256 == filters.sha256.lower())
    if filters.filename_contains:
        statement = statement.where(Scan.filename.ilike(f"%{filters.filename_contains}%"))
    if filters.min_risk_score is not None:
        statement = statement.where(Scan.risk_score >= filters.min_risk_score)
    if filters.created_after is not None:
        statement = statement.where(Scan.created_at >= filters.created_after)
    if filters.created_before is not None:
        statement = statement.where(Scan.created_at <= filters.created_before)
    return statement


async def get_stats(session: AsyncSession) -> ScanStats:
    """Aggregate counters for the dashboard."""
    since = datetime.now(UTC) - timedelta(hours=24)

    total = int((await session.execute(select(func.count(Scan.id)))).scalar_one())

    by_status_rows = (
        await session.execute(select(Scan.status, func.count(Scan.id)).group_by(Scan.status))
    ).all()
    by_verdict_rows = (
        await session.execute(select(Scan.verdict, func.count(Scan.id)).group_by(Scan.verdict))
    ).all()

    scanned_24h = int(
        (
            await session.execute(select(func.count(Scan.id)).where(Scan.created_at >= since))
        ).scalar_one()
    )
    malicious_24h = int(
        (
            await session.execute(
                select(func.count(Scan.id)).where(
                    Scan.created_at >= since, Scan.verdict == Verdict.MALICIOUS
                )
            )
        ).scalar_one()
    )
    avg_duration = (
        await session.execute(
            select(func.avg(Scan.duration_ms)).where(Scan.status == ScanStatus.COMPLETED)
        )
    ).scalar_one()
    ai_calls = int(
        (
            await session.execute(
                select(func.count(AIAssessment.id)).where(AIAssessment.created_at >= since)
            )
        ).scalar_one()
    )

    return ScanStats(
        total=total,
        by_status={str(status.value): int(count) for status, count in by_status_rows},
        by_verdict={str(verdict.value): int(count) for verdict, count in by_verdict_rows},
        scanned_last_24h=scanned_24h,
        malicious_last_24h=malicious_24h,
        avg_duration_ms=float(avg_duration) if avg_duration is not None else None,
        ai_calls_last_24h=ai_calls,
    )


async def recent_scans(session: AsyncSession, limit: int = 20) -> list[Scan]:
    statement = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    return list((await session.execute(statement)).scalars().all())


async def find_by_hash(session: AsyncSession, sha256: str) -> list[Scan]:
    statement = (
        select(Scan).where(Scan.sha256 == sha256.lower()).order_by(Scan.created_at.desc()).limit(50)
    )
    return list((await session.execute(statement)).scalars().all())
