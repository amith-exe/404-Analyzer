from celery import Celery
from app.config import settings

celery_app = Celery(
    "scanner",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.scan_pipeline"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)
