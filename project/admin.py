from django.contrib import admin

from .models import Project, Keyword, Suggestion, Asset

# Register your models here.

admin.site.register(Project)
admin.site.register(Keyword)
admin.site.register(Suggestion)
admin.site.register(Asset)
