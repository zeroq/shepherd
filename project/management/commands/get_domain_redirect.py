import socket
import uuid
import dateparser
import requests
from urllib.parse import urlparse
from django.core.management.base import BaseCommand
from project.models import Suggestion
from datetime import datetime, timezone
from django.utils.timezone import make_aware


class Command(BaseCommand):
    help = "Check for domain redirections and update the redirect_to field in Suggestion objects."

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )

    def handle(self, *args, **kwargs):
        # Filter suggestions by project ID if provided
        project_filter = {}
        if kwargs['projectid']:
            project_filter['related_project__id'] = kwargs['projectid']

        # Filter suggestions where active is not 'False'
        suggestions = Suggestion.objects.exclude(active=False).filter(**project_filter).filter(finding_type='domain')

        for suggestion in suggestions:
            domain = suggestion.value
            final_domain = self.check_redirect(domain)

            final_suggestion = None
            if final_domain and final_domain != domain:
                # Find or create the Suggestion object for the final domain
                final_domain_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{final_domain}:{kwargs['projectid']}")
                final_suggestion, _ = Suggestion.objects.get_or_create(
                    value = final_domain,
                    uuid = final_domain_uuid,
                    defaults={
                        "related_project": suggestion.related_project,
                        "source": "Redirect",
                        "description": f"Redirected from {domain}",
                        "active": True,
                        "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                    },
                )
                self.stdout.write(f"{domain} redirects to {final_domain}")
                # exit(0)
            else:
                self.stdout.write(f"{domain} does not redirect.")

            # Update the redirect_to field
            suggestion.redirect_to = final_suggestion
            suggestion.save()

    def check_redirect(self, domain):
        """
        Check if the domain redirects and return the final domain.
        """
        for scheme, port in [("https", 443), ("http", 80)]:
            url = f"{scheme}://{domain}"
            try:
                # Check if the port is open
                with socket.create_connection((domain, port), timeout=5):
                    # Follow redirections
                    response = requests.get(url, allow_redirects=True, timeout=10)
                    final_url = response.url
                    parsed_url = urlparse(final_url)
                    return parsed_url.netloc  # Return the final domain
            except (socket.error, requests.RequestException):
                continue  # Try the next scheme/port
        return None