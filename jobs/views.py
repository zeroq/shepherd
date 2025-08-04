from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from project.models import Project, Suggestion, ActiveDomain, Job
from django.views.decorators.csrf import csrf_exempt

@login_required
def jobs(request):
    if not request.user.has_perm('project.view_job'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}

    return render(request, 'jobs/list_jobs.html', context)

@login_required
def view_job(request, job_id):
    """view job details
    """
    if not request.user.has_perm('project.view_job'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        j_obj = Job.objects.get(id=job_id)
    except Job.DoesNotExist:
        messages.error(request, 'Unknown Job: %s' % job_id)
        return redirect(reverse('jobs:jobs'))
    
    context = {
        'projectid': request.session['current_project']['prj_id'],
        'j_obj': j_obj,
    }

    return render(request, 'jobs/view_job.html', context)
