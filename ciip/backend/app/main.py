import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api import admin, ai, auth, decisions, incidents, intake, intel, reports
from app.core.config import get_settings
from app.core.kv import MemoryKV, get_kv
from app.db import SessionLocal

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("ciip")

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    if isinstance(get_kv(), MemoryKV) and settings.redis_url:
        log.warning("Redis injoignable : stockage en mémoire (révocation et limitation non partagées)")
    yield


app = FastAPI(
    title="Cyber Incident & Intelligence Platform",
    version="1.0.0",
    description="Plateforme de gestion d'incidents cyber et de renseignement sur la menace — V1 (données fictives).",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Organization-Id", "X-Intake-Token"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if not request.url.path.startswith("/api/docs"):
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        response.headers.setdefault("Cache-Control", "no-store")
    if settings.is_production:
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    # Never leak stack traces or SQL to clients.
    log.exception("Erreur non gérée sur %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Erreur interne"})


API = "/api/v1"
for module in (auth, incidents, intake, intel, ai, decisions, reports, admin):
    app.include_router(module.router, prefix=API)


@app.get("/api/health", tags=["santé"])
def health() -> dict:
    db_ok = True
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "database": db_ok,
            "redis": not isinstance(get_kv(), MemoryKV), "version": app.version}
