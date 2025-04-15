import django.forms.fields
from django import forms
from django.forms import ModelForm

from project.models import Project, Suggestion


class AddSuggestionForm(ModelForm):
    description = forms.CharField(required=False, widget=forms.Textarea)

    class Meta:
        model = Suggestion
        fields = ['value', 'related_project', 'related_keyword', 'finding_type', 'finding_subtype', 'source', 'description', 'link']

    def __init__(self, *args, **kwargs):
        super(AddSuggestionForm, self).__init__(*args, **kwargs)
        self.fields['value'].widget.attrs.update({'class': 'form-control'})
        self.fields['related_project'].widget.attrs.update({'class': 'form-control'})
        self.fields['related_keyword'].widget.attrs.update({'class': 'form-control'})
        self.fields['finding_type'].widget.attrs.update({'class': 'form-control'})
        self.fields['finding_subtype'].widget.attrs.update({'class': 'form-control'})        
        self.fields['source'].widget.attrs.update({
            'class': 'form-control',
            'value': 'manual',
        })
        self.fields['description'].widget.attrs.update({'class': 'form-control'})
        self.fields['link'].widget.attrs.update({'class': 'form-control'})
