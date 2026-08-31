import logging
import warnings
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import SAWarning
from database import engine, Base
from routers import tools, scans, findings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress harmless SQLAlchemy identity map warnings
warnings.filterwarnings("ignore", category=SAWarning, message=".*Identity map already had an identity.*")


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    # Migrate: add columns that may not exist in older databases
    with engine.connect() as conn:
        for stmt in [
            "ALTER TABLE scans ADD COLUMN progress JSON",
            "ALTER TABLE findings ADD COLUMN triage_state TEXT",
            "ALTER TABLE findings ADD COLUMN commit_hash TEXT",
            "ALTER TABLE findings ADD COLUMN commit_author TEXT",
            "ALTER TABLE findings ADD COLUMN commit_date TEXT",
            "ALTER TABLE scans ADD COLUMN parent_scan_id INTEGER REFERENCES scans(id)",
            "ALTER TABLE scans ADD COLUMN version INTEGER DEFAULT 1",
            "ALTER TABLE findings ADD COLUMN is_duplicate INTEGER DEFAULT 0",
            "ALTER TABLE findings ADD COLUMN duplicate_ids JSON",
            "ALTER TABLE scans ADD COLUMN source_type TEXT DEFAULT 'path'",
            "ALTER TABLE scans ADD COLUMN image_ref TEXT",
        ]:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                pass  # column already exists
    logger.info("Database initialised")
    yield


app = FastAPI(title="Sasty SAST", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(findings.router, prefix="/api/findings", tags=["findings"])

import os

@app.get("/api/info")
def get_info():
    """Return environment info for the frontend."""
    from services import image_scanner
    is_docker = os.path.exists("/.dockerenv") or os.environ.get("SASTY_DOCKER") == "1"
    # Image filesystem extraction prefers crane (a bundled static registry
    # client) and falls back to a local docker daemon. Image scanning itself
    # only needs trivy.
    backend = image_scanner.extraction_backend()
    return {
        "is_docker": is_docker,
        "image_extract_available": backend is not None,
        "image_extract_backend": backend,
    }

# Serve the built frontend from /app/frontend/dist if it exists
frontend_dist = Path(__file__).parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        return FileResponse(str(frontend_dist / "index.html"))
