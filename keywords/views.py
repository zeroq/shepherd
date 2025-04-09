# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from project.models import Project, Keyword
from keywords.forms import AddKeywordForm
from project.models import Suggestion
from django.core.management import call_command
import threading

@login_required
def keywords(request):
    project_id = request.session['current_project']['prj_id']
    keyword_form = AddKeywordForm()
    descriptions = (
        Suggestion.objects.filter(related_project_id=project_id)
        .exclude(description__isnull=True)
        .exclude(description__exact="")
        .values_list('description', flat=True)
        .distinct()
    )
    context = {
        'projectid': project_id,
        'keywordform': keyword_form,
        'descriptions': descriptions
    }
    return render(request, 'keywords/list_keywords.html', context)

@login_required
def toggle_keyword(request, keywordid):
    try:
        kw_obj = Keyword.objects.get(id=keywordid)
    except Keyword.DoesNotExist:
        kw_obj = None
    if kw_obj is not None:
        kw_obj.enabled = not kw_obj.enabled
        kw_obj.save()
    return redirect(reverse('keywords:keywords'))

@login_required
def delete_keyword(request, keywordid):
    try:
        kw_obj = Keyword.objects.get(id=keywordid).delete()
    except Keyword.DoesNotExist:
        return redirect(reverse('keywords:keywords'))
    return redirect(reverse('keywords:keywords'))

@login_required
def add_keyword(request):
    prjid = request.session['current_project']['prj_id']
    if request.method == 'POST':
        form = AddKeywordForm(request.POST)
        if form.is_valid():
            try:
                prj_obj = Project.objects.get(id=prjid)
            except Exception as error:
                messages.error(request, "Project not found!")
                return redirect(reverse('keywords:keywords'))
            data = {
                'keyword': form.cleaned_data['keyword'],
                'ktype': form.cleaned_data['ktype'],
                'description': form.cleaned_data['description'],
                'related_project': prj_obj
            }
            Keyword.objects.get_or_create(**data)
            messages.info(request, "Comment successfully added")
    return redirect(reverse('keywords:keywords'))

@login_required
def scan_domaintools(request):
    context = {'projectid': request.session['current_project']['prj_id']}
    messages.info(request, 'Domaintools scan against monitored keywords has been triggered in the background.')

    try:
        # Get the project ID from the session
        projectid = context['projectid']

        # Define a function to run the command in a separate thread
        def run_command():
            try:
                call_command('import_domaintools', projectid=projectid)
            except Exception as e:
                print(f"Error running import_domaintools: {e}")

        # Start the thread
        thread = threading.Thread(target=run_command)
        thread.start()

    except Exception as e:
        messages.error(request, f'Error: {e}')
    return redirect(reverse('keywords:keywords'))

@login_required
def scan_crtsh(request):
    context = {'projectid': request.session['current_project']['prj_id']}
    messages.info(request, 'CRTSH scan against monitored keywords has been triggered in the background.')

    try:
        # Get the project ID from the session
        projectid = context['projectid']

        # Define a function to run the command in a separate thread
        def run_command():
            try:
                call_command('import_crtsh', projectid=projectid)
            except Exception as e:
                print(f"Error running import_crtsh: {e}")

        # Start the thread
        thread = threading.Thread(target=run_command)
        thread.start()

    except Exception as e:
        messages.error(request, f'Error: {e}')
    return redirect(reverse('keywords:keywords'))
