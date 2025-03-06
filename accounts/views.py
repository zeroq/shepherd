from django.shortcuts import render, redirect

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
