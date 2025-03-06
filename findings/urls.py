from django.urls import path
from findings import views

urlpatterns = [
    path('', views.assets, name='assets'),
    path('ignored/', views.ignored_assets, name='ignored_assets'),
    path('ignore/<str:uuid>/', views.ignore_asset, name='ignore_asset'),
    path('move/<str:uuid>/', views.move_asset, name='move_asset'),
    path('activate/<str:uuid>/', views.activate_asset, name='activate_asset'),
    path('delete/<str:uuid>/', views.delete_asset, name='delete_asset'),
    path('view/<str:uuid>/', views.view_asset, name='view_asset'),
    path('view/reported/<str:uuid>/', views.view_asset_reported, name='view_asset_reported'),
    path('asset/<str:uuid>/finding/<str:findingid>/delete/<str:reported>/', views.delete_finding, name='delete_finding'),
    path('send/<str:uuid>/finding/<str:findingid>/nucleus/', views.send_nucleus, name='send_nucleus'),
    #path('delete/<str:uuid>/ignored/', views.delete_suggestion_ignored, name='delete_suggestion_ignored'),
    path('recent/findings/', views.recent_findings, name='recent_findings'),
    path('all/unignore/', views.unignore_all_assets, name='unignore_all_assets'),
]

