# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db import connection
from rest_framework import status
from rest_framework.pagination import LimitOffsetPagination, PageNumberPagination
from rest_framework.response import Response
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator as DjangoPaginator
from django.utils.functional import cached_property

class APICustomPaginator(DjangoPaginator):

    @cached_property
    def count(self):
        try:
            with connection.cursor() as cursor:
                table_name = self.object_list.model._meta.db_table
                cursor.execute("SELECT reltuples::BIGINT AS estimate FROM pg_class WHERE relname='%s';" % (table_name))
                row = cursor.fetchone()
                return row[0]
        except:
            try:
                return self.object_list.count()
            except (AttributeError, TypeError):
                # AttributeError if object_list has no count() method.
                # TypeError if object_list.count() requires arguments
                # (i.e. is of type list).
                return len(self.object_list)

class CustomPaginator(PageNumberPagination):
    django_paginator_class = APICustomPaginator

    def get_page_size(self, request):
        if request.query_params:
            return int(request.query_params.get('length', 25))
        else:
            return 25

    def paginate_queryset(self, queryset, request, view=None):
        page_size = self.get_page_size(request)
        paginator = self.django_paginator_class(queryset, page_size)
        if request.query_params and 'start' in request.query_params:
            page_number = int(int(request.query_params['start'])/int(page_size))+1
        elif request.query_params and 'page' in request.query_params:
            page_number = int(request.query_params['page'])
        else:
            page_number = 1
        try:
            self.page = paginator.page(page_number)
        except:
            self.page = 1
        self.request = request
        return list(self.page)

    def get_paginated_response(self, data):
        return JsonResponse({
            "status": True,
            "code": status.HTTP_200_OK,
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'count': self.page.paginator.count,
            'iTotalRecords': self.page.paginator.count,
            'iTotalDisplayRecords': self.page.paginator.count,
            'results': data
        })
