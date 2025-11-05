from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.http import HttpResponse
from ratelimit.decorators import ratelimit


@ratelimit(key='ip', rate='5/m', method='POST', block=True)  # default for anonymous users
def login_view(request):
    """
    Simple login view with rate limiting.
    Anonymous users: 5 requests per minute
    Authenticated users: 10 requests per minute
    """
    # If the user is authenticated, apply a higher rate limit
    if request.user.is_authenticated:
        return authenticated_login_view(request)

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return HttpResponse("Login successful.")
        else:
            return HttpResponse("Invalid credentials.", status=401)

    return render(request, 'login.html')


@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)
def authenticated_login_view(request):
    """Rate limit for authenticated users (10/min)."""
    return HttpResponse("Authenticated user request allowed.")

