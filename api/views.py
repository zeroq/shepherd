from datetime import datetime, timedelta

from django.shortcuts import render
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.db.models import Q, Prefetch, Count, F
from django.conf import settings
from django.utils.timezone import make_aware

from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, TokenAuthentication

from api.pagination import CustomPaginator
from api.serializer import ProjectSerializer, KeywordSerializer, SuggestionSerializer, ActiveDomainSerializer, FindingSerializer, PortSerializer
from api.utils import get_ordering_vars

from project.models import Project, Keyword, Suggestion, ActiveDomain
from findings.models import Finding, Port

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
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})

    ### get search parameters
    search_value = request.query_params.get('columns[1][search][value]', None)
    search_source = request.query_params.get('columns[2][search][value]', None)
    search_description = request.query_params.get('columns[3][search][value]', None)
    search_redirect_to = request.query_params.get('columns[4][search][value]', None)
    search_creation_date = request.query_params.get('columns[5][search][value]', None)
    search_active = request.query_params.get('columns[6][search][value]', None)
    print(f"Search: {search_value}, {search_source}, {search_description}, {search_creation_date}, {search_active}")  # Debugging statement

    ### create queryset
    if selection in ['ignored']:
        queryset = prj.suggestion_set.filter(ignore=True)
    else:
        queryset = prj.suggestion_set.filter(ignore=False)  # Do not display ignored suggestions

    if vtype in ['domain', 'subdomain', 'ipaddress']:
        queryset = queryset.filter(finding_subtype=vtype)

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

    if search_active and len(search_active) > 1:
        queryset = queryset.filter(
            Q(active__icontains=search_active)
        )

    print(f"Filtered queryset count: {queryset.count()}")  # Debugging statement

    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='creation_time',
                                                         default_direction='-')

    ### order queryset
    if order_by_column:
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')

    suggestions = paginator.paginate_queryset(queryset, request)

    # for suggestion in suggestions:
    #     suggestion.redirect_to_value = (
    #         suggestion.redirect_to.value if suggestion.redirect_to else None
    #     )

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
        queryset = queryset.filter(
            Q(vuln_info__icontains=search_columns['vulns']) |
            Q(vuln_critical__icontains=search_columns['vulns']) |
            Q(vuln_high__icontains=search_columns['vulns']) |
            Q(vuln_medium__icontains=search_columns['vulns']) |
            Q(vuln_low__icontains=search_columns['vulns'])
        )

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
    if order_by_column:
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
    paginator = CustomPaginator()

    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})

    ### create queryset
    active_domains = prj.activedomain_set.all().filter(monitor=True)
    queryset = Finding.objects.filter(domain__in=active_domains)

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