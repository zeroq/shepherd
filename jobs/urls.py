from django.urls import path
from jobs import views

urlpatterns = [
    # Jobs stuffs
    path('', views.jobs, name='jobs'),
    path('scheduled_jobs/', views.scheduled_jobs, name='scheduled_jobs'),
    path('view/<int:job_id>/', views.view_job, name='view_job'),
]
