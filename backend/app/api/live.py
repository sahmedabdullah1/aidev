"""Live server connection endpoints."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.models.live_schemas import LiveConnectRequest, LiveConnectResponse, LiveStatusResponse
from app.services.live_monitor import live_monitor

router = APIRouter(prefix="/live", tags=["live"])


@router.post("/connect", response_model=LiveConnectResponse)
async def live_connect(body: LiveConnectRequest) -> LiveConnectResponse:
    try:
        result = await live_monitor.connect(body)
    except FileNotFoundError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"Could not connect: {exc}") from exc
    return LiveConnectResponse(**result)


@router.post("/disconnect")
async def live_disconnect() -> dict[str, str]:
    await live_monitor.disconnect()
    return {"status": "disconnected"}


@router.get("/status", response_model=LiveStatusResponse)
async def live_status() -> LiveStatusResponse:
    return LiveStatusResponse.model_validate(live_monitor.public_state())


@router.get("/snapshot")
async def live_snapshot() -> dict:
    return live_monitor.public_state()


@router.post("/analyze-now")
async def live_analyze_now() -> dict[str, str | None]:
    try:
        job_id = await live_monitor.analyze_now()
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not job_id:
        raise HTTPException(400, "No log window collected yet — wait for traffic or check log paths")
    return {
        "status": "queued",
        "job_id": job_id,
        "message": "Live window queued for AI report — poll /api/jobs/{job_id}",
    }


@router.get("/stream")
async def live_stream() -> StreamingResponse:
    async def events():
        q: asyncio.Queue = asyncio.Queue(maxsize=4)
        live_monitor.subscribe(q)
        try:
            yield f"data: {json.dumps(live_monitor.public_state(), default=str)}\n\n"
            while True:
                try:
                    item = await asyncio.wait_for(q.get(), timeout=20)
                    yield f"data: {json.dumps(item, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            live_monitor.unsubscribe(q)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
