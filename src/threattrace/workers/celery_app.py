from __future__ import annotations

from celery import Celery
from kombu import Exchange, Queue

from threattrace.config.settings import get_settings

settings = get_settings()

if not settings.redis_url:
    raise RuntimeError("Redis URL is required for Celery broker/backend configuration")

celery_app = Celery(
    "threattrace",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "threattrace.workers.pipeline",
        "threattrace.workers.recovery",
        "threattrace.workers.process_reports",
    ],
)

celery_app.conf.update(
    # Time / UTC
    enable_utc=True,
    timezone="UTC",
    # Serialization
    task_serializer="json",
    event_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    # Reliability
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=None,
    broker_transport_options={
        "visibility_timeout": 21600,
        "socket_timeout": 30,
        "socket_connect_timeout": 30,
        "retry_on_timeout": True,
        "retry_policy": {
            "interval_start": 0,
            "interval_step": 0.5,
            "interval_max": 5,
        },
    },
    result_backend_transport_options={
        "visibility_timeout": 21600,
        "retry_policy": {
            "timeout": 30.0,
        },
    },

    # Result backend
    result_expires=86400,

    # Task execution safety
    task_soft_time_limit=settings.celery_task_soft_timeout,
    task_time_limit=settings.celery_task_hard_timeout,

    # Worker stability
    worker_max_tasks_per_child=25,
    worker_send_task_events=True,
    worker_enable_remote_control=True,
    task_send_sent_event=True,

    # Routing
    task_default_queue="threattrace",
    task_default_exchange="threattrace",
    task_default_exchange_type="direct",
    task_default_routing_key="threattrace",
    task_create_missing_queues=False,
    task_queues=(
        Queue(
            "threattrace",
            Exchange("threattrace"),
            routing_key="threattrace",
            durable=True,
        ),
    ),
    task_routes={
        "threattrace.workers.pipeline.*": {
            "queue": "threattrace",
            "routing_key": "threattrace",
        },
        "threattrace.workers.recovery.*": {
            "queue": "threattrace",
            "routing_key": "threattrace",
        },
        "threattrace.workers.process_reports.*": {
            "queue": "threattrace",
            "routing_key": "threattrace",
        },
    },

    # Imports
    imports=(
        "threattrace.workers.pipeline",
        "threattrace.workers.recovery",
        "threattrace.workers.process_reports",
    ),

    # Worker persistence / observability
    worker_hijack_root_logger=False,

    # Result handling
    task_ignore_result=False,
    result_persistent=True,
    result_backend_always_retry=True,

    # Heartbeat / connection resilience
    broker_heartbeat=30,
    broker_pool_limit=20,
    redis_backend_health_check_interval=30,

    # Retry / failure handling
    task_acks_on_failure_or_timeout=True,
    task_default_retry_delay=30,
)


app = celery_app
