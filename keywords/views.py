# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.http import HttpResponseForbidden
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from project.models import Project, Keyword, Asset
from keywords.forms import AddKeywordForm
from django.core.management import call_command
import threading
from django.utils.html import escape

from jobs.utils import run_job

@login_required
def keywords(request):
    if not request.user.has_perm('project.view_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    project_id = request.session['current_project']['prj_id']
    add_keyword_form = AddKeywordForm()
    
    descriptions = (
        Asset.objects.filter(related_project_id=project_id)
        .exclude(description__isnull=True)
        .exclude(description__exact="")
        .filter(description__icontains="registrant")
        .values_list('description', flat=True)
        .distinct()
    )
    context = {
        'projectid': project_id,
        'addkeywordform': add_keyword_form,
        'descriptions': descriptions
    }
    return render(request, 'keywords/list_keywords.html', context)

@login_required
def toggle_keyword(request, keywordid):
    if not request.user.has_perm('project.change_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
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
    if not request.user.has_perm('project.delete_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        kw_obj = Keyword.objects.get(id=keywordid).delete()
    except Keyword.DoesNotExist:
        return redirect(reverse('keywords:keywords'))
    return redirect(reverse('keywords:keywords'))

@login_required
def add_keyword(request):
    if not request.user.has_perm('project.add_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
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
                'keyword': escape(form.cleaned_data['keyword']),
                'ktype': form.cleaned_data['ktype'],
                'description': escape(form.cleaned_data['description']),
                'related_project': prj_obj
            }
            Keyword.objects.get_or_create(**data)
            messages.info(request, "Comment successfully added")
    return redirect(reverse('keywords:keywords'))

@login_required
def scan_keywords(request):
    if not request.user.has_perm('project.add_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    if request.method == 'POST':
        context = {'projectid': request.session['current_project']['prj_id']}
        
        if "crtsh" in request.POST:
            messages.info(request, 'CRTSH scan against monitored keywords has been triggered in the background.')

            try:
                # Get the project ID from the session
                projectid = context['projectid']

                # Define a function to run the command in a separate thread
                def run_command():
                    try:
                        command = 'import_crtsh'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running import_crtsh: {e}")

                # Start the thread
                thread = threading.Thread(target=run_command)
                thread.start()

            except Exception as e:
                messages.error(request, f'Error: {e}')

        if "domaintools" in request.POST:
            messages.info(request, 'DomainTools scan against monitored keywords has been triggered in the background.')

            try:
                # Get the project ID from the session
                projectid = context['projectid']

                # Define a function to run the command in a separate thread
                def run_command():
                    try:
                        command = 'import_domaintools'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running import_domaintools: {e}")

                # Start the thread
                thread = threading.Thread(target=run_command)
                thread.start()

            except Exception as e:
                messages.error(request, f'Error: {e}')

        if "shodan" in request.POST:
            messages.info(request, 'Shodan scan against monitored keywords has been triggered in the background.')
            try:
                projectid = context['projectid']
                def run_command():
                    try:
                        command = 'import_shodan'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running import_shodan: {e}")
                thread = threading.Thread(target=run_command)
                thread.start()
            except Exception as e:
                messages.error(request, f'Error: {e}')

        if "porch-pirate" in request.POST:
            messages.info(request, 'Porch-pirate scan against monitored keywords has been triggered in the background.')
            try:
                projectid = context['projectid']
                def run_command():
                    try:
                        command = 'scan_porch-pirate'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running scan_porch-pirate: {e}")
                thread = threading.Thread(target=run_command)
                thread.start()
            except Exception as e:
                messages.error(request, f'Error: {e}')

        if "swaggerhub" in request.POST:
            messages.info(request, 'SwaggerHub scan against monitored keywords has been triggered in the background.')
            try:
                projectid = context['projectid']
                def run_command():
                    try:
                        command = 'scan_swaggerhub'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running scan_swaggerhub: {e}")
                thread = threading.Thread(target=run_command)
                thread.start()
            except Exception as e:
                messages.error(request, f'Error: {e}')

        if "ai_scribd" in request.POST:
            messages.info(request, 'AI powered Scribd scan against monitored keywords has been triggered in the background.')
            try:
                projectid = context['projectid']
                def run_command():
                    try:
                        command = 'scan_ai_scribd'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running scan_ai_scribd: {e}")
                thread = threading.Thread(target=run_command)
                thread.start()
            except Exception as e:
                messages.error(request, f'Error: {e}')


    return redirect(reverse('keywords:keywords'))
