from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api.live import router as live_router
from app.api.routes import router
from app.config import get_settings
from app.db.database import init_db
from app.models.schemas import WebhookAck
from app.services.live_monitor import live_monitor
from app.webhooks.gitlab import handle_gitlab_webhook


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    await init_db()
    yield
    await live_monitor.disconnect()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        description="AI DevOps — investigate repos, logs, and infra; auto-report on GitLab events.",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list or ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router, prefix="/api")
    app.include_router(live_router, prefix="/api")

    @app.post("/api/webhooks/gitlab", response_model=WebhookAck, include_in_schema=True)
    async def gitlab_hook(
        request: Request,
        x_gitlab_token: str | None = Header(default=None, alias="X-Gitlab-Token"),
    ) -> WebhookAck:
        payload = await request.json()
        return await handle_gitlab_webhook(payload, header_token=x_gitlab_token)

    @app.get("/")
    async def root():
        return {
            "app": settings.app_name,
            "docs": "/docs",
            "health": "/api/health",
            "wso2_analyze": "POST /api/wso2/analyze",
            "live_connect": "POST /api/live/connect",
            "live_stream": "GET /api/live/stream",
            "investigate": "POST /api/investigate",
            "gitlab_webhook": "POST /api/webhooks/gitlab",
        }

    return app


app = create_app()
