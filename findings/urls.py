from django.urls import path
from findings import views

urlpatterns = [
    # Assets stuffs
    path('', views.assets, name='assets'),
    # path('ignored/', views.ignored_assets, name='ignored_assets'),
    path('ignore/<str:uuid>/', views.ignore_asset_glyphicon, name='ignore_asset_glyphicon'),
    path('move/all/', views.move_all_assets, name='move_all_assets'),
    path('move/<str:uuid>/', views.move_asset, name='move_asset'),
    path('delete/<str:uuid>/', views.delete_asset, name='delete_asset'),
    path('activate/all/', views.activate_all_assets, name='activate_all_assets'),
    path('activate/<str:uuid>/', views.activate_asset, name='activate_asset'),
    path('view/reported/<str:uuid>/', views.view_asset_reported, name='view_asset_reported'),
    path('view/<str:uuid>/', views.view_asset, name='view_asset'),
    path('asset/<str:uuid>/finding/<str:findingid>/delete/<str:reported>/', views.delete_finding, name='delete_finding'),
    path('send/<str:uuid>/finding/<str:findingid>/nucleus/', views.send_nucleus, name='send_nucleus'),
    #path('delete/<str:uuid>/ignored/', views.delete_suggestion_ignored, name='delete_suggestion_ignored'),

    # Nmap stuffs
    path('nmap/results/', views.nmap_results, name='nmap_results'),

    # Scanner stuffs
    path('scan_assets/', views.scan_assets, name='scan_assets'),
    path('scanners/results', views.all_findings, name='all_findings'),
    # path('view/finding', views.all_findings, name='view_finding'),
]

