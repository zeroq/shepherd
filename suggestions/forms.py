import django.forms.fields
from django import forms
from django.forms import ModelForm

from project.models import Project, Suggestion


class AddSuggestionForm(ModelForm):
    description = forms.CharField(required=False, widget=forms.Textarea)
    finding_type = forms.ChoiceField(
        choices=[('domain', 'domain'), ('starred_domain', 'starred_domain')],
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    finding_subtype = forms.ChoiceField(
        choices=[('domain', 'domain'), ('subdomain', 'subdomain')],
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = Suggestion
        fields = ['value', 'finding_type', 'finding_subtype', 'source', 'description']

    def __init__(self, *args, **kwargs):
        super(AddSuggestionForm, self).__init__(*args, **kwargs)
        self.fields['value'].widget.attrs.update({'class': 'form-control'})
        self.fields['source'].widget.attrs.update({
            'class': 'form-control',
            'value': 'manual',
        })
        self.fields['description'].widget.attrs.update({'class': 'form-control'})
