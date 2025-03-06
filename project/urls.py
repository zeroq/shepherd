from django.urls import path
from project import views

urlpatterns = [
    path('', views.projects, name='projects'),
    path('add/', views.add_project, name='add_project'),
    path('<int:projectid>/select/', views.select_project, name='select_project'),
]

