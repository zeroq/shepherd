from django.urls import path
from suggestions import views

urlpatterns = [
    path('', views.suggestions, name='suggestions'),
    path('scan_redirects/', views.scan_redirects, name='scan_redirects'),
    path('ignored/', views.ignored_suggestions, name='ignored_suggestions'),
    path('manual/add/', views.manual_add_suggestion, name='manual_add_suggestion'),
    path('update/', views.update_suggestions, name='update_suggestions'),
    path('recent/', views.recent_suggestions, name='recent_suggestions'),
    path('ignore/star/', views.ignore_star_suggestions, name='ignore_star_suggestions'),
    path('ignore/<str:uuid>/', views.ignore_suggestion, name='ignore_suggestion'),
    path('monitor/<str:uuid>/', views.monitor_suggestion, name='monitor_suggestion'),
    path('monitor/all/unique/', views.monitor_all_unique_domains, name='monitor_all_unique_domains'),
    path('reactivate/<str:uuid>/', views.reactivate_suggestion, name='reactivate_suggestion'),
    path('delete/<str:uuid>/', views.delete_suggestion, name='delete_suggestion'),
    path('delete/<str:uuid>/ignored/', views.delete_suggestion_ignored, name='delete_suggestion_ignored'),
    path('all/delete/', views.delete_all_suggestions, name='delete_all_suggestions'),
    path('upload_suggestions/', views.upload_suggestions, name='upload_suggestions'),
]
