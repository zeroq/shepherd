import django.forms.fields
from django import forms
from django.forms import ModelForm

from project.models import Keyword

class AddKeywordForm(ModelForm):
    description = forms.CharField(required=False, widget=forms.Textarea)

    class Meta:
        model = Keyword
        fields = ['keyword', 'description']

    def __init__(self, *args, **kwargs):
        super(AddKeywordForm, self).__init__(*args, **kwargs)
        self.fields['keyword'].widget.attrs.update({'class': 'form-control'})
        self.fields['description'].widget.attrs.update({'class': 'form-control'})
