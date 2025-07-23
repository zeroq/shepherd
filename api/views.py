from datetime import datetime, timedelta

from django.shortcuts import render
from django.http import HttpResponseForbidden, JsonResponse, HttpResponse, HttpResponseRedirect
from django.db.models import Q, Prefetch, Count, F
from django.conf import settings
from django.utils.timezone import make_aware

from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, TokenAuthentication

from api.pagination import CustomPaginator
from api.serializer import JobSerializer, ProjectSerializer, KeywordSerializer, SuggestionSerializer, ActiveDomainSerializer, FindingSerializer, PortSerializer, ScreenshotSerializer
from api.utils import get_ordering_vars

from project.models import Project, Keyword, Suggestion, ActiveDomain, Job
from findings.models import Finding, Port, Screenshot

# Create your views here.

##### PROJECTS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_projects(request, format=None):
    """List all projects
    """
    if not request.user.has_perm('project.view_project'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
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
    if search_value and len(search_value) > 1:
        queryset = queryset.filter(
            Q(projectname__icontains=search_value) |
            Q(description__istartswith=search_value)
        )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_modified',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        order = f"{'-' if order_direction == '-' else ''}{order_by_column}"
        queryset = queryset.order_by(order)

    paginator = CustomPaginator()
    prjs = paginator.paginate_queryset(queryset, request)
    serializer = ProjectSerializer(instance=prjs, many=True)

    return paginator.get_paginated_response(serializer.data)


@api_view(['POST'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def create_project(request, format=None):
    """Create project via API
    """
    if not request.user.has_perm('project.add_project'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
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
    if not request.user.has_perm('project.view_suggestion'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})

    ### get search parameters
    search_value = request.query_params.get('columns[1][search][value]', None)
    search_source = request.query_params.get('columns[2][search][value]', None)
    search_description = request.query_params.get('columns[3][search][value]', None)
    search_redirect_to = request.query_params.get('columns[4][search][value]', None)
    search_creation_date = request.query_params.get('columns[5][search][value]', None)
    search_monitor = request.query_params.get('columns[6][search][value]', None)
    search_active = request.query_params.get('columns[7][search][value]', None)
    # print(f"Search: {search_value}, {search_source}, {search_description}, {search_creation_date}, {search_active}, {search_monitor}")  # Debugging statement

    ### create queryset
    if selection in ['ignored']:
        queryset = prj.suggestion_set.filter(ignore=True)
    else:
        queryset = prj.suggestion_set.filter(ignore=False)  # Do not display ignored suggestions

    if vtype in ['domain']:
        queryset = queryset.filter(finding_type='domain')
    elif vtype in ['starred_domain']:
        queryset = queryset.filter(finding_type=vtype)
    elif vtype in ['second_level_domain']:
        queryset = queryset.filter(finding_type='domain', finding_subtype='domain')

    ### filter by search value
    if search_value and len(search_value) > 1:
        queryset = queryset.filter(
            Q(value__icontains=search_value)
        )
    if search_source and len(search_source) > 1:
        queryset = queryset.filter(
            Q(source__icontains=search_source)
        )
    if search_description and len(search_description) > 1:
        queryset = queryset.filter(
            Q(description__icontains=search_description)
        )
    ### Annotate the queryset with redirect_to.value
    queryset = queryset.annotate(redirect_to_value=F('redirect_to__value'))
    if search_redirect_to and len(search_redirect_to) > 1:
        queryset = queryset.filter(
            Q(redirect_to_value__icontains=search_redirect_to)
        )
    if search_creation_date and len(search_creation_date) > 1:
        queryset = queryset.filter(
            Q(creation_time__icontains=search_creation_date)
        )
    if search_monitor is not None and search_monitor != '':
        if search_monitor.lower() == 'true':
            queryset = queryset.filter(monitor=True)
        elif search_monitor.lower() == 'false':
            queryset = queryset.filter(monitor=False)
        elif search_monitor.lower() == 'none':
            queryset = queryset.filter(monitor__isnull=True)
    if search_active is not None and search_active != '':
        if search_active.lower() == 'true':
            queryset = queryset.filter(active=True)
        elif search_active.lower() == 'false':
            queryset = queryset.filter(active=False)
        elif search_active.lower() == 'none':
            queryset = queryset.filter(active__isnull=True)

    # print(f"Filtered queryset count: {queryset.count()}")  # Debugging statement

    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='creation_time',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')

    suggestions = paginator.paginate_queryset(queryset, request)
    serializer = SuggestionSerializer(instance=suggestions, many=True)

    # Modify the serialized data to include the redirect_to_value
    serialized_data = serializer.data
    for item, suggestion in zip(serialized_data, suggestions):
        item['redirect_to'] = suggestion.redirect_to_value

    return paginator.get_paginated_response(serialized_data)


##### END SUGGESTIONS ###########


##### ASSETS ###############
@api_view(['GET'])
@authentication_classes((SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def list_assets(request, projectid, selection, format=None):
    if not request.user.has_perm('project.view_activedomain'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({
            "status": True,
            "code": 200,
            "next": None,
            "previous": None,
            "count": 0,
            "iTotalRecords": 0,
            "iTotalDisplayRecords": 0,
            "results": []
        })

    ### get search parameters
    search_value = request.query_params.get('search[value]', None)
    search_columns = {
        'value': request.query_params.get('columns[1][search][value]', None),
        'vulns': request.query_params.get('columns[2][search][value]', None),
        'source': request.query_params.get('columns[3][search][value]', None),
        'description': request.query_params.get('columns[4][search][value]', None),
        'lastscan_time': request.query_params.get('columns[5][search][value]', None),
        'creation_time': request.query_params.get('columns[6][search][value]', None),
    }

    ### create queryset
    if selection in ['monitored']:
        queryset = prj.activedomain_set.filter(monitor=True)
    else:
        queryset = prj.activedomain_set.filter(monitor=False)

    # Annotate vulnerabilities
    queryset = queryset.annotate(
        vuln_info=Count('finding', filter=Q(finding__severity='info')),
        vuln_critical=Count('finding', filter=Q(finding__severity='critical')),
        vuln_high=Count('finding', filter=Q(finding__severity='high')),
        vuln_medium=Count('finding', filter=Q(finding__severity='medium')),
        vuln_low=Count('finding', filter=Q(finding__severity='low'))
    )

    ### filter by global search value
    if search_value and len(search_value) > 1:
        queryset = queryset.filter(
            Q(value__icontains=search_value) |
            Q(description__icontains=search_value) |
            Q(source__icontains=search_value)
        )

    ### filter by column-specific search values
    if search_columns['value']:
        queryset = queryset.filter(value__icontains=search_columns['value'])

    if search_columns['vulns']:
        # Map severity keywords to annotated fields
        severity_map = {
            'info': 'vuln_info',
            'critical': 'vuln_critical',
            'high': 'vuln_high',
            'medium': 'vuln_medium',
            'low': 'vuln_low',
        }
        severity_filter = search_columns['vulns'].lower()
        if severity_filter in severity_map:
            queryset = queryset.filter(**{f"{severity_map[severity_filter]}__gt": 0})

    if search_columns['source']:
        queryset = queryset.filter(source__icontains=search_columns['source'])

    if search_columns['description']:
        queryset = queryset.filter(description__icontains=search_columns['description'])

    if search_columns['lastscan_time']:
        queryset = queryset.filter(lastscan_time__icontains=search_columns['lastscan_time'])

    if search_columns['creation_time']:
        queryset = queryset.filter(creation_time__icontains=search_columns['creation_time'])

    ### get variables
    order_by_column, order_direction = get_ordering_vars(
        request.query_params,
        default_column='creation_time',
        default_direction='-'
    )

    ### order queryset
    if order_by_column and order_by_column != "vulns":
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')

    ### paginate queryset
    assets = paginator.paginate_queryset(queryset, request)
    serializer = ActiveDomainSerializer(instance=assets, many=True)
    return paginator.get_paginated_response(serializer.data)


##### END ASSETS ###########

##### KEYWORDS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_keywords(request, projectid, selection, format=None):
    if not request.user.has_perm('project.view_keyword'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
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
    if not request.user.has_perm('project.add_keyword'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    prjname = request.data.get('projectname', None)
    keywords = request.data.get('keywords', None)
    if prjname is not None:
        try:
            prj_obj = Project.objects.get(projectname=prjname)
        except Project.DoesNotExist:
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

##### PORTS ###############
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_ports(request, projectid, format=None):
    if not request.user.has_perm('findings.view_port'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})

    # Fetch all active domains associated with the project
    active_domains = ActiveDomain.objects.filter(related_project=prj)

    # Define queryset to filter ports by active domains
    queryset = Port.objects.filter(domain__in=active_domains)

    # Get search parameters
    search_value = request.query_params.get('search[value]', None)
    if search_value and len(search_value) > 1:
        queryset = queryset.filter(
            Q(port__icontains=search_value) |
            Q(banner__icontains=search_value) |
            Q(status__icontains=search_value) |
            Q(product__icontains=search_value) |
            Q(cpe__icontains=search_value)
        )

    search_domain_name = request.query_params.get('columns[1][search][value]', None)
    search_port = request.query_params.get('columns[2][search][value]', None)
    search_banner = request.query_params.get('columns[3][search][value]', None)
    search_cpe = request.query_params.get('columns[4][search][value]', None)
    search_last_scan = request.query_params.get('columns[5][search][value]', None)
    # print(f"Search: {search_domain_name}, {search_port}, {search_banner}, {search_cpe}, {search_last_scan}")  # Debugging statement

    ### filter by search value
    if search_domain_name and len(search_domain_name) > 1:
        queryset = queryset.filter(
            Q(domain_name__icontains=search_domain_name)
        )

    if search_port and len(search_port) > 1:
        queryset = queryset.filter(
            Q(port__icontains=search_port)
        )

    if search_banner and len(search_banner) > 1:
        queryset = queryset.filter(
            Q(banner__icontains=search_banner)
        )

    if search_cpe and len(search_cpe) > 1:
        queryset = queryset.filter(
            Q(cpe__icontains=search_cpe)
        )

    if search_last_scan and len(search_last_scan) > 1:
        queryset = queryset.filter(
            Q(scan_date__icontains=search_last_scan)
        )

    # Get ordering variables
    order_by_column, order_direction = get_ordering_vars(request.query_params, default_column='scan_date', default_direction='-')

    # Order queryset
    if order_by_column:
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')

    # Paginate queryset
    ports = paginator.paginate_queryset(queryset, request)
    serializer = PortSerializer(instance=ports, many=True)

    return paginator.get_paginated_response(serializer.data)

##### END PORTS ###############


##### FINDINGS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_recent_findings(request, projectid, severity, format=None):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    if severity not in ['info', 'low', 'medium', 'high', 'critical']:
        print("ERROR: wrong severity: %s" % severity)
        severity = 'info'
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
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


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_all_findings(request, projectid, format=None):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()

    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})

    ### create queryset
    active_domains = prj.activedomain_set.all().filter(monitor=True)
    queryset = Finding.objects.filter(domain__in=active_domains)
    # Filter by reported status if provided
    reported_param = request.query_params.get('reported', None)
    if reported_param is not None:
        if reported_param.lower() == 'reported':
            queryset = queryset.filter(last_reported__isnull=False)
        elif reported_param.lower() == 'not_reported':
            queryset = queryset.filter(last_reported__isnull=True)

    # Get search parameters
    search_value = request.query_params.get('search[value]', None)
    if search_value and len(search_value) > 1:
        queryset = queryset.filter(
            Q(name__icontains=search_value)|
            Q(description__icontains=search_value)
        )

    search_domain_name = request.query_params.get('columns[1][search][value]', None)
    search_name = request.query_params.get('columns[2][search][value]', None)
    search_type = request.query_params.get('columns[3][search][value]', None)
    search_description = request.query_params.get('columns[4][search][value]', None)
    search_cve = request.query_params.get('columns[5][search][value]', None)
    search_severity = request.query_params.get('columns[6][search][value]', None)
    search_scan_date = request.query_params.get('columns[7][search][value]', None)
    # print(f"Search: {search_domain_name}, {search_port}, {search_banner}, {search_cpe}, {search_last_scan}")  # Debugging statement

    ### filter by search value
    if search_domain_name and len(search_domain_name) > 1:
        queryset = queryset.filter(
            Q(domain_name__icontains=search_domain_name)
        )

    if search_name and len(search_name) > 1:
        queryset = queryset.filter(
            Q(name__icontains=search_name)
        )

    if search_type and len(search_type) > 1:
        queryset = queryset.filter(
            Q(type__icontains=search_type)
        )

    if search_description and len(search_description) > 1:
        queryset = queryset.filter(
            Q(description__icontains=search_description)
        )

    if search_cve and len(search_cve) > 1:
        queryset = queryset.filter(
            Q(cve__icontains=search_cve)
        )

    if search_severity and len(search_severity) > 1:
        queryset = queryset.filter(
            Q(severity__icontains=search_severity)
        )

    if search_scan_date and len(search_scan_date) > 1:
        queryset = queryset.filter(
            Q(scan_date__icontains=search_scan_date)
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

@api_view(['DELETE'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def delete_finding(request, projectid, findingid):
    """Delete a specific finding by ID for a given project."""
    if not request.user.has_perm('findings.delete_finding'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    try:
        # Check if the project exists
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'message': 'Project does not exist', 'status': 'failure'}, status=404)

    try:
        # Check if the finding exists and belongs to the project
        finding = Finding.objects.get(id=findingid, domain__related_project=prj)
        finding.delete()
        return JsonResponse({'message': 'Finding successfully deleted', 'status': 'success'}, status=200)
    except Finding.DoesNotExist:
        return JsonResponse({'message': 'Finding does not exist', 'status': 'failure'}, status=404)

##### END FINDINGS ###########

##### JOBS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_jobs(request, projectid):
    if not request.user.has_perm('project.view_job'):
        return HttpResponseForbidden("You do not have permission to view this.")

    # check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({
            "status": True,
            "code": 200,
            "next": None,
            "previous": None,
            "count": 0,
            "iTotalRecords": 0,
            "iTotalDisplayRecords": 0,
            "results": []
        })

    queryset = Job.objects.filter(related_project=prj).order_by('-created_at')
    queryset = queryset.annotate(username=F('user__username'))

    paginator = CustomPaginator()
    jobs = paginator.paginate_queryset(queryset, request)
    serializer = JobSerializer(instance=jobs, many=True)
    data = serializer.data

    # Add username to each job in the response
    for job_obj, job_instance in zip(data, jobs):
        job_obj['username'] = getattr(job_instance, 'username', None)

    return paginator.get_paginated_response(data)

##### END JOBS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def list_screenshots(request, projectid, format=None):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission to view this project.")

    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({
            "draw": int(request.GET.get('draw', 1)),
            "recordsTotal": 0,
            "recordsFiltered": 0,
            "data": []
        })

    # Filtering and search
    domains = prj.activedomain_set.all()
    queryset = Screenshot.objects.filter(domain__in=domains).order_by('-date')

    # DataTables search on columns
    search_columns = [
        request.GET.get('columns[0][search][value]', ''),  # url
        '',  # screenshot (not searchable)
        request.GET.get('columns[2][search][value]', ''),  # technologies
        request.GET.get('columns[3][search][value]', ''),  # title
        request.GET.get('columns[4][search][value]', ''),  # status_code
        request.GET.get('columns[5][search][value]', ''),  # webserver
        request.GET.get('columns[6][search][value]', ''),  # date
    ]
    if search_columns[0]:
        queryset = queryset.filter(url__icontains=search_columns[0])
    if search_columns[2]:
        queryset = queryset.filter(technologies__icontains=search_columns[2])
    if search_columns[3]:
        queryset = queryset.filter(title__icontains=search_columns[3])
    if search_columns[4]:
        queryset = queryset.filter(status_code__icontains=search_columns[4])
    if search_columns[5]:
        queryset = queryset.filter(webserver__icontains=search_columns[5])
    if search_columns[6]:
        queryset = queryset.filter(date__icontains=search_columns[6])

    # Global search
    search_value = request.GET.get('search[value]', '')
    if search_value:
        queryset = queryset.filter(
            Q(url__icontains=search_value) |
            Q(technologies__icontains=search_value) |
            Q(title__icontains=search_value) |
            Q(status_code__icontains=search_value) |
            Q(webserver__icontains=search_value)
        )

    # Ordering
    order_column_index = request.GET.get('order[0][column]', None)
    order_dir = request.GET.get('order[0][dir]', 'desc')
    order_columns = ['url', '', 'technologies', 'title', 'status_code', 'webserver', 'date']
    if order_column_index is not None:
        idx = int(order_column_index)
        if order_columns[idx]:
            order_field = order_columns[idx]
            if order_dir == 'desc':
                order_field = '-' + order_field
            queryset = queryset.order_by(order_field)

    # Pagination
    # start = int(request.GET.get('start', 0))
    # length = int(request.GET.get('length', 25))
    # total = queryset.count()
    # page = queryset[start:start+length]

    # data = []
    # for s in page:
    #     data.append({
    #         'url': s.url,
    #         'screenshot_base64': s.screenshot_base64,
    #         'technologies': s.technologies,
    #         'title': s.title,
    #         'status_code': s.status_code,
    #         'webserver': s.webserver,
    #         'date': s.date.strftime('%Y-%m-%d %H:%M:%S'),
    #     })

    # return JsonResponse({
    #     'draw': int(request.GET.get('draw', 1)),
    #     'recordsTotal': total,
    #     'recordsFiltered': total,
    #     'data': data,
    # })

    paginator = CustomPaginator()
    screenshots = paginator.paginate_queryset(queryset, request)
    serializer = ScreenshotSerializer(instance=screenshots, many=True)
    data = serializer.data

    return paginator.get_paginated_response(data)
