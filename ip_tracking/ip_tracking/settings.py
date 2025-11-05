from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'detect-suspicious-ips-hourly': {
        'task': 'ip_tracking.tasks.detect_suspicious_ips',
        'schedule': crontab(minute=0, hour='*'),  # every hour
    },
}

INSTALLED_APPS = [
    # Django default apps...
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Custom apps
    'ip_tracking',

    # Third-party app for rate limiting
    'ratelimit',
]

# Optional: customize rate limit behavior
RATELIMIT_VIEW = 'ratelimit.views.ratelimited'  # default behavior
RATELIMIT_FAIL = 'ratelimit.exceptions.Ratelimited'  # or use a custom handler
