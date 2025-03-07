# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render
from django.contrib.auth.decorators import login_required

from project.models import Project, Keyword

@login_required
def home(request):
    context = {}
    # number of projects
    prj = Project.objects.all().count()
    context['projects'] = prj
    # number of keywords
    kw = Keyword.objects.all().count()
    context['keywords'] = kw
    #request.session['current_project'] = None
    return render(request, 'shepherd/index.html', context)


#@login_required
#def projects(request):
#    context = {}
#    return render(request, 'shepherd/list_projects.html', context)
