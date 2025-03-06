
from datetime import datetime, timedelta

from django.shortcuts import render
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.db.models import Q, Prefetch, Count
from django.conf import settings
from django.utils.timezone import make_aware

from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, TokenAuthentication

from api.pagination import CustomPaginator
from api.serializer import ProjectSerializer, KeywordSerializer, SuggestionSerializer, ActiveDomainSerializer, FindingSerializer
from api.utils import get_ordering_vars

from project.models import Project, Keyword, Suggestion, ActiveDomain
from findings.models import Finding

# Create your views here.

##### PROJECTS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_projects(request, format=None):
    """List all projects
    """
    paginator = CustomPaginator()
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    queryset = Project.objects.all()
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(projectname__icontains=search_value)|
            Q(description__istartswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_modified',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    prjs = paginator.paginate_queryset(queryset, request)
    serializer = ProjectSerializer(instance=prjs, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(['POST'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def create_project(request, format=None):
    """Create project via API
    """
    prj_serializer = ProjectSerializer(data=request.data)
    if prj_serializer.is_valid():
        prj_serializer.save()
        result = {'message': 'Project successfully created', 'status': 'success'}
    else:
        result = {'message': 'Project failed to create: %s' % (prj_serializer.errors), 'status': 'failure'}
    return JsonResponse(result)


##### END PROJECTS ###############

##### SUGGESTIONS ################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_suggestions(request, projectid, selection, vtype, format=None):
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})
    ### get search parameters
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    if selection in ['ignored']:
        queryset = prj.suggestion_set.all().filter(ignore=True).filter(is_monitored=False)
    else:
        queryset = prj.suggestion_set.all().filter(ignore=False).filter(is_monitored=False) # Do not display ignored suggestions
    if vtype in ['domain', 'subdomain', 'ipaddress']:
        queryset = queryset.filter(finding_subtype=vtype)
    else:
        pass
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(value__icontains=search_value)|
            Q(description__icontains=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='creation_time',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    kwrds = paginator.paginate_queryset(queryset, request)
    serializer = SuggestionSerializer(instance=kwrds, many=True)
    return paginator.get_paginated_response(serializer.data)


##### END SUGGESTIONS ###########


##### ASSETS ###############
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_assets(request, projectid, selection, format=None):
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})
    ### get search parameters
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    if selection in ['monitored']:
        queryset = prj.activedomain_set.all().filter(monitor=True)
        queryset = queryset.annotate(vuln_info=Count('finding', filter=Q(finding__severity='info')))
        queryset = queryset.annotate(vuln_critical=Count('finding', filter=Q(finding__severity='critical')))
        queryset = queryset.annotate(vuln_high=Count('finding', filter=Q(finding__severity='high')))
        queryset = queryset.annotate(vuln_medium=Count('finding', filter=Q(finding__severity='medium')))
        queryset = queryset.annotate(vuln_low=Count('finding', filter=Q(finding__severity='low')))
    else:
        queryset = prj.activedomain_set.all().filter(monitor=False) # Do not display ignored assets
        queryset = queryset.annotate(vuln_info=Count('finding', filter=Q(finding__severity='info')))
        queryset = queryset.annotate(vuln_critical=Count('finding', filter=Q(finding__severity='critical')))
        queryset = queryset.annotate(vuln_high=Count('finding', filter=Q(finding__severity='high')))
        queryset = queryset.annotate(vuln_medium=Count('finding', filter=Q(finding__severity='medium')))
        queryset = queryset.annotate(vuln_low=Count('finding', filter=Q(finding__severity='low')))
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(value__icontains=search_value)|
            Q(description__icontains=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='creation_time',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    kwrds = paginator.paginate_queryset(queryset, request)
    serializer = ActiveDomainSerializer(instance=kwrds, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_recent_findings(request, projectid, severity, format=None):
    paginator = CustomPaginator()
    if severity not in ['info', 'low', 'medium', 'high', 'critical']:
        print("ERROR: wrong severity: %s" % severity)
        severity = 'info'
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})
    ### get search parameters
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    five_days = datetime.now() - timedelta(days=settings.RECENT_DAYS) # X days ago
    recent_active_domains = prj.activedomain_set.all().filter(monitor=True, lastscan_time__gte=make_aware(five_days))
    queryset = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, severity=severity)
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(vulnname__icontains=search_value)|
            Q(description__icontains=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_seen',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    kwrds = paginator.paginate_queryset(queryset, request)
    serializer = FindingSerializer(instance=kwrds, many=True)
    return paginator.get_paginated_response(serializer.data)





##### END ASSETS ###########

##### KEYWORDS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_keywords(request, projectid, selection, format=None):
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})
    ### get search parameters
    if request.query_params:
        if 'search[value]' in request.query_params:
            search_value = request.query_params['search[value]']
        else:
            search_value = None
    else:
        search_value = None
    ### create queryset
    if selection in ['enabled']:
        queryset = prj.keyword_set.all().filter(enabled=True)
    elif selection in ['disabled']:
        queryset = prj.keyword_set.all().filter(enabled=False)
    else:
        queryset = prj.keyword_set.all()
    ### filter by search value
    if search_value and len(search_value)>1:
        queryset = queryset.filter(
            Q(keyword__icontains=search_value)|
            Q(description__istartswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_modified',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    kwrds = paginator.paginate_queryset(queryset, request)
    serializer = KeywordSerializer(instance=kwrds, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(['POST'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def add_keyword(request, format=None):
    """Add keywords to a project
    """
    prjname = request.data.get('projectname', None)
    keywords = request.data.get('keywords', None)
    if prjname is not None:
        try:
            prj_obj = Project.objects.get(projectname=prjname)
        except project.DoesNotExist:
            result = {'message': 'Given project does not exist', 'status': 'failure'}
            return JsonResponse(result)
    if keywords is None:
        result = {'message': 'No keywords given', 'status': 'failure'}
        return JsonResponse(result)
    if type(keywords)==type([]):
        for k in keywords:
            obj = {'related_project': prj_obj, 'keyword': k}
            kobj, created = Keyword.objects.get_or_create(**obj)
    elif type(keywords)==type(""):
        obj = {'related_project': prj_obj, 'keyword': keywords}
        kobj, created = Keyword.objects.get_or_create(**obj)
    else:
        result = {'message': 'Wrong datatype given: %s' % (type(keywords)), 'status': 'failure'}
        return JsonResponse(result)
    result = {'message': 'Keywords successfully created', 'status': 'success'}
    return JsonResponse(result)



##### END KEYWORDS ###############
