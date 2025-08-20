import html
import tempfile
from urllib.parse import urlencode, quote_plus
import subprocess
from project.models import Project, Keyword, Suggestion
from findings.models import Finding
import re
import json
import requests
from openai import AzureOpenAI

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.conf import settings

from django.utils.timezone import make_aware
from datetime import datetime

class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )

    def handle(self, *args, **options):
        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(f"Project: {prj.projectname}")
            for kw in prj.keyword_set.all():
                if not kw.enabled:
                    continue
                keyword = html.unescape(kw.keyword)
                if kw.ktype == "ai_scribd_keyword":
                    self.stdout.write("[+] Scribd search: {}".format(keyword))
                    self.ai_scribd_scan(kw, prj)

    def ai_scribd_scan(self, kw, prj):
        keyword = html.unescape(kw.keyword)
        prompt = f"Search Scribd for documents related to the keyword: '{keyword}'. Summarize any sensitive findings."
        prompt = f"Can you search the internet?"

        # Azure OpenAI Foundry endpoint and key (replace with your values)
        endpoint = settings.AI_API_ENDPOINT
        model = "gpt-4o"
        # deployment = "gpt-4o-mini-2"
        
        subscription_key = settings.AI_API_KEY
        api_version = "2024-12-01-preview"
        
        client = AzureOpenAI(
            api_version=api_version,
            azure_endpoint=endpoint,
            api_key=subscription_key,
        )

        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}]
            )
            ai_output = response.choices[0].message.content if response.choices else ""
            self.stdout.write(f"[+] Azure AI Foundry response for '{keyword}':\n{ai_output}")
        except Exception as error:
            self.stderr.write(f"[+] Error calling Azure AI Foundry: {error}")
