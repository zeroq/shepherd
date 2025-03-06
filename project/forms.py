import django.forms.fields
from django import forms
from django.forms import ModelForm

from project.models import Project

class AddProjectForm(ModelForm):
    description = forms.CharField(required=False, widget=forms.Textarea)

    class Meta:
        model = Project
        fields = ['projectname', 'description']

    def __init__(self, *args, **kwargs):
        super(AddProjectForm, self).__init__(*args, **kwargs)
        self.fields['projectname'].widget.attrs.update({'class': 'form-control'})
        self.fields['description'].widget.attrs.update({'class': 'form-control'})
