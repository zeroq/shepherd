
from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns

from api import views

urlpatterns = [
    # project APIs
    path('v1/projects/', views.list_projects, name='list_projects'),
    path('v1/project/create/', views.create_project, name='create_project'),
    path('v1/project/<str:projectid>/keywords/<str:selection>/', views.list_keywords, name='list_keywords'),
    path('v1/project/<str:projectid>/suggestions/<str:selection>/<str:vtype>/', views.list_suggestions, name='list_suggestions'),
    path('v1/project/<str:projectid>/assets/<str:selection>/', views.list_assets, name='list_assets'),
    path('v1/project/<str:projectid>/recent/<str:severity>/', views.list_recent_findings, name='list_recent_findings'),
    #path('v1/project/<str:projectid>/modify/', views.modify_project, name='modify_project'),
    #path('v1/project/<str:projectid>/delete/', views.delete_project, name='delete_project'),
    # keyword APIs
    path('v1/keyword/add/', views.add_keyword, name='add_keyword'),

]

urlpatterns = format_suffix_patterns(urlpatterns)
