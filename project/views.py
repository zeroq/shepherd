# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from .models import Project
from .forms import AddProjectForm

@login_required
def projects(request):
    context = {'projectform': AddProjectForm(), 'num_total_domains': 0, 'num_total_subdomains': 0, 'num_total_ipaddresses': 0, 'num_ignored_domains': 0, 'num_ignored_subdomains': 0, 'num_ignored_ipaddresses': 0}
    if 'current_project' in request.session and request.session['current_project'] is not None:
        # load project
        prj = Project.objects.get(id=request.session['current_project']['prj_id'])
        #print(prj)
        context['project_name'] = prj.projectname
        # get suggestions
        context['num_total_domains'] = prj.suggestion_set.filter(finding_type='domain', finding_subtype='domain').count()
        context['num_ignored_domains'] = prj.suggestion_set.filter(finding_type='domain', finding_subtype='domain', ignore=True).count()
        context['num_total_subdomains'] = prj.suggestion_set.filter(finding_type='domain', finding_subtype='subdomain').count()
        context['num_ignored_subdomains'] = prj.suggestion_set.filter(finding_type='domain', finding_subtype='subdomain', ignore=True).count()
        #context['num_total_ipaddresses'] = prj.suggestion_set.filter(finding_type='domain', finding_subtype='subdomain').count()
        #context['num_total_ipaddresses'] = prj.suggestion_set.filter(finding_type='domain', finding_subtype='subdomain', ignore=True).count()
        context['num_total_total'] = context['num_total_domains']+context['num_total_subdomains']+context['num_total_ipaddresses']
        context['num_ignored_total'] = context['num_ignored_domains']+context['num_ignored_subdomains']+context['num_ignored_ipaddresses']

    return render(request, 'projects/list_projects.html', context)

@login_required
def select_project(request, projectid):
    context = {}
    try:
        prj_obj = Project.objects.get(id=projectid)
        prj_name = prj_obj.projectname
        prj_id = prj_obj.id
    except Project.DoesNotExist:
        print('ERROR: project not existing')
        prj_obj = None
        prj_name = None
        prj_id = None
    if prj_obj is not None:
        request.session['current_project'] = {'prj_id': prj_id, 'prj_name': prj_name}
    else:
        request.session['current_project'] = None
    #return render(request, 'projects/list_projects.html', context)
    return redirect(reverse('projects:projects'))

@login_required
def add_project(request):
    if request.method == 'POST':
        form = AddProjectForm(request.POST)
        if form.is_valid():
            form.save()
            messages.info(request, "Project successfully added")
    return redirect(reverse('projects:projects'))
