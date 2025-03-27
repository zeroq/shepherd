import django.forms.fields
from django import forms
from django.forms import ModelForm

from project.models import Keyword

class AddKeywordForm(ModelForm):
    KTYPE_CHOICES = [
        ('registrant_org', 'Registrant Organization'),
        ('registrant_email', 'Registrant Email'),
        ('registrant_email_domain', 'Registrant Email Domain'),
        ('crtsh_domain', 'Domain for CRTSH'),
    ]

    ktype = forms.ChoiceField(choices=KTYPE_CHOICES, required=True, label="Keyword type")
    description = forms.CharField(required=False, widget=forms.Textarea)

    class Meta:
        model = Keyword
        fields = ['keyword', 'ktype', 'description']

    def __init__(self, *args, **kwargs):
        super(AddKeywordForm, self).__init__(*args, **kwargs)
        self.fields['keyword'].widget.attrs.update({'class': 'form-control'})
        self.fields['ktype'].widget.attrs.update({'class': 'form-control'})
        self.fields['description'].widget.attrs.update({'class': 'form-control'})
