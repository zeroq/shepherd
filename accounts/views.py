from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.http import JsonResponse

# Create your views here.

from django_ratelimit.decorators import ratelimit

from django.shortcuts import render
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages

# Create your views here.

@ratelimit(key='ip', method=ratelimit.ALL, rate='5/m')
def accounts_login(request):
    context = {}
    if request.user.is_authenticated:
        return HttpResponseRedirect(reverse("home"))
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect(reverse('home'))
            else:
                messages.error(request, '%s: is not activated!' % (username))
        else:
            messages.error(request, 'Logon failed!')
        return HttpResponseRedirect(reverse("accounts:login"))
    return render(request, 'accounts/login.html', context)

@ratelimit(key='ip', method=ratelimit.ALL, rate='5/m')
def sso_login(request):
    """
    Handle SSO login.
    """
    if request.user.is_authenticated:
        return HttpResponseRedirect(reverse("home"))

    sso_token = request.GET.get('sso_token')
    if not sso_token:
        messages.error(request, 'SSO token is missing.')
        return HttpResponseRedirect(reverse("accounts:login"))

    # Simulate SSO token validation and user retrieval
    user_data = validate_sso_token(sso_token)
    if not user_data:
        messages.error(request, 'Invalid SSO token.')
        return HttpResponseRedirect(reverse("accounts:login"))

    user, created = User.objects.get_or_create(username=user_data['username'], defaults={
        'email': user_data['email'],
        'first_name': user_data['first_name'],
        'last_name': user_data['last_name'],
    })

    if created:
        user.set_unusable_password()  # SSO users won't have a local password
        user.save()

    login(request, user)
    return HttpResponseRedirect(reverse("home"))

def validate_sso_token(token):
    """
    Simulate SSO token validation. Replace this with actual SSO validation logic.
    """
    # Example mock data for demonstration purposes
    mock_sso_data = {
        "valid_token": {
            "username": "sso_user",
            "email": "sso_user@example.com",
            "first_name": "SSO",
            "last_name": "User"
        }
    }
    return mock_sso_data.get(token)

@login_required
def accounts_logout(request):
    logout(request)
    messages.info(request, 'Successfully logged out.')
    return HttpResponseRedirect(reverse("accounts:login"))

@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('accounts:change_password')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'accounts/chgpwd.html', {'form': form})
