import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine
from app.models.models import Base
from app.api.routes import router

logging.basicConfig(level=settings.log_level)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Tables are managed by Alembic; this is a fallback for local dev
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Outside-In Cloud Visibility Scanner",
    description="Hackathon MVP: subdomain enumeration, crawling, and vulnerability scanning.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}
