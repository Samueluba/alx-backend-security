from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'detect-suspicious-ips-hourly': {
        'task': 'ip_tracking.tasks.detect_suspicious_ips',
        'schedule': crontab(minute=0, hour='*'),  # every hour
    },
}

