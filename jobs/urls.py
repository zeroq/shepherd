from django.urls import path
from jobs import views

urlpatterns = [
    # Jobs stuffs
    path('', views.jobs, name='jobs'),
    path('view/<int:job_id>', views.view_job, name='view_job'),
    # path('view/<str:uuid>/', views.view_asset, name='view_asset'),

]
