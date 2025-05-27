from django.urls import path
from keywords import views

urlpatterns = [
    path('', views.keywords, name='keywords'),
    path('add/', views.add_keyword, name='add_keyword'),

    path('scan_keywords/', views.scan_keywords, name='scan_keywords'),

    path('<int:keywordid>/toggle/', views.toggle_keyword, name='toggle_keyword'),
    path('<int:keywordid>/delete/', views.delete_keyword, name='delete_keyword'),
]

