from datetime import timedelta
from django.utils import timezone
from celery import shared_task
from django.db.models import Count
from ip_tracking.models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login', '/accounts/login', '/user/login']


@shared_task
def detect_suspicious_ips():
    """
    Hourly Celery task that flags suspicious IPs based on:
      - More than 100 requests in the past hour
      - Access to sensitive paths (/admin, /login, etc.)
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # --- 1. Detect high-volume IPs ---
    recent_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)
    ip_counts = recent_logs.values('ip_address').annotate(req_count=Count('id'))

    for record in ip_counts:
        ip = record['ip_address']
        count = record['req_count']

        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={'reason': f"High traffic volume: {count} requests in the past hour."}
            )

    # --- 2. Detect sensitive path access ---
    sensitive_logs = recent_logs.filter(path__in=SENSITIVE_PATHS)
    for log in sensitive_logs:
        SuspiciousIP.objects.get_or_create(
            ip_address=log.ip_address,
            defaults={'reason': f"Accessed sensitive path: {log.path}"}
        )

    return "Anomaly detection completed."

