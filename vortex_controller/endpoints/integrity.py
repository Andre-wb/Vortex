"""GET /v1/integrity — status of the source-code attestation."""
from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(prefix="/v1", tags=["integrity"])


@router.get("/integrity")
async def integrity(request: Request) -> dict:
    report = getattr(request.app.state, "integrity", None)
    if report is None:
        return {
            "status": "unknown",
            "message": "Integrity verification has not run yet.",
        }
    return report.to_dict()
