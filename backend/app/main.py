import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import auth, fixes, settings, workflow, azure
from .api.findings import router as findings_router
from .api.ingest import router as ingest_router
from .api.scan import router as scan_router
from .api.scan_status import router as scan_status_router
from .api.sentryai import router as sentryai_router
from .database import init_db

app = FastAPI(
    title="Sentinel - Guardian of the Digital Frontier",
    version="1.0.0",
    description="Automated recon + AI-triaged threats for the lawless web.",
)

# Allow CORS from the frontend (Vite dev server + any deployed origin).
_allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://localhost:3000",
    os.getenv("FRONTEND_ORIGIN", ""),
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in _allowed_origins if o],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(scan_router, prefix="/api")
app.include_router(findings_router, prefix="/api")
app.include_router(workflow.router, prefix="/api")
app.include_router(fixes.router, prefix="/api")
app.include_router(scan_status_router, prefix="/api")
app.include_router(settings.router, prefix="/api")
app.include_router(ingest_router, prefix="/api")
app.include_router(azure.router, prefix="/api")
app.include_router(sentryai_router, prefix="/api/sentry")


@app.on_event("startup")
def _startup():
    # Initialise sqlite tables (harmless if already present).
    init_db()


@app.get("/")
async def root():
    return {
        "message": "Sentinel API is running",
        "status": "ok",
        "version": "1.0.0",
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
