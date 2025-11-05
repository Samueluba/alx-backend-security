from .models import RequestLog
from datetime import datetime

class IPTrackingMiddleware:
    """Middleware to log IP address, timestamp, and path of incoming requests."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get the IP address (supports proxied requests)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

        # Log request details to the database
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path
        )

        response = self.get_response(request)
        return response

from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP


class IPTrackingMiddleware:
    """Middleware to log IP address, timestamp, and path of incoming requests,
    and block blacklisted IPs."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get client IP (support proxies)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')

        # --- Block if IP is blacklisted ---
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: Your IP address is blocked.")

        # --- Log the request ---
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path
        )

        response = self.get_response(request)
        return response
