# celery.py (in your project root directory, same level as settings.py)
import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ai_vtm.settings')

app = Celery('ai_vtm')

# Load config from Django settings with CELERY namespace
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all registered Django apps
app.autodiscover_tasks()

# Celery Beat Schedule for periodic tasks
app.conf.beat_schedule = {
    'cleanup-old-remediations': {
        'task': 'vulnerabilities.tasks.cleanup_old_remediations',
        'schedule': crontab(hour=2, minute=0),  # Run daily at 2 AM
    },
    'update-vector-db': {
        'task': 'vulnerabilities.tasks.update_vector_db_from_helpful_remediations',
        'schedule': crontab(hour=3, minute=0),  # Run daily at 3 AM
    },
}

# Celery configuration
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')