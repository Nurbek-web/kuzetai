"""Read-only camera API with bounded filters and credential redaction."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from protector.pilot.api.auth import ServerSession
from protector.pilot.api.dependencies import ApiContext, get_context, get_current_session
from protector.pilot.storage.models import CameraModel

router = APIRouter(prefix="/api/cameras", tags=["cameras"])


@router.get("")
def list_cameras(
    current: Annotated[ServerSession, Depends(get_current_session)],
    context: Annotated[ApiContext, Depends(get_context)],
    site_id: str | None = None,
    state: Literal["starting", "online", "degraded", "offline", "reconnecting"] | None = None,
    enabled: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> dict[str, object]:
    del current
    filters = [
        expression
        for expression in (
            CameraModel.site_id == site_id if site_id is not None else None,
            CameraModel.state == state if state is not None else None,
            CameraModel.enabled == enabled if enabled is not None else None,
        )
        if expression is not None
    ]
    statement = select(CameraModel)
    count_statement = select(func.count()).select_from(CameraModel)
    if filters:
        statement = statement.where(*filters)
        count_statement = count_statement.where(*filters)
    statement = statement.order_by(CameraModel.camera_id).offset(offset).limit(limit)
    with context.repository.session_factory() as session:
        rows = list(session.scalars(statement))
        total = int(session.scalar(count_statement) or 0)
    return {
        "items": [
            {
                "camera_id": row.camera_id,
                "site_id": row.site_id,
                "name": row.name,
                "codec": row.codec,
                "state": row.state,
                "enabled": row.enabled,
                "created_at": row.created_at,
            }
            for row in rows
        ],
        "limit": limit,
        "offset": offset,
        "total": total,
    }
