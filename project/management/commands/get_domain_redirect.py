import socket
import uuid
import dateparser
import requests
import tldextract
from urllib.parse import urlparse
from django.core.management.base import BaseCommand
from project.models import Suggestion
from datetime import datetime, timezone
from django.utils.timezone import make_aware
from concurrent.futures import ThreadPoolExecutor, as_completed


class Command(BaseCommand):
    help = "Check for domain redirections and update the redirect_to field in Suggestion objects."

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )
        parser.add_argument(
            '--uuids',
            type=str,
            help='Comma separated list of suggestion UUIDs to process',
            required=False,
        )

    def handle(self, *args, **kwargs):
        # Filter suggestions by project ID if provided
        project_filter = {}
        if kwargs['projectid']:
            project_filter['related_project__id'] = kwargs['projectid']

        uuids_arg = kwargs.get('uuids')

        # Filter suggestions where active is not 'False'
        suggestions = Suggestion.objects.exclude(active=False).filter(**project_filter).filter(finding_type='domain')

        # Filter by uuids if provided
        if uuids_arg:
            uuid_list = [u.strip() for u in uuids_arg.split(",") if u.strip()]
            suggestions = suggestions.filter(uuid__in=uuid_list)

        def process_suggestion(suggestion, projectid):
            domain = suggestion.value
            final_domain = self.check_redirect(domain)

            final_suggestion = None
            if final_domain and final_domain != domain:

                # Create the suggestion details for the final domain
                sugg = {
                    "finding_type": "domain",
                    "related_project": suggestion.related_project,
                    "source": "redirect",
                    "description": f"Redirected from {domain}",
                    "active": True,
                    "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                }

                # Check if domain or subdomain
                parsed_obj = tldextract.extract(final_domain)
                if parsed_obj.subdomain:
                    sugg["finding_subtype"] = 'subdomain'
                else:
                    sugg["finding_subtype"] = 'domain'

                # Create suggestion entry
                final_domain_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{final_domain}:{projectid}")
                final_suggestion, created = Suggestion.objects.get_or_create(
                    value = final_domain,
                    uuid = final_domain_uuid,
                    defaults=sugg,
                )

                if not created:
                    final_suggestion.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                    if not 'redirect' in final_suggestion.source:
                        final_suggestion.source = final_suggestion.source + ", redirect"
                    final_suggestion.save()

                self.stdout.write(f"{domain} redirects to {final_domain}")
                # exit(0)
            else:
                self.stdout.write(f"{domain} does not redirect.")

            # Update the redirect_to field
            suggestion.redirect_to = final_suggestion
            suggestion.save()

        # Parallelize the processing of suggestions
        projectid = kwargs.get('projectid')
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(process_suggestion, suggestion, projectid) for suggestion in suggestions]
            for future in as_completed(futures):
                future.result()  # Raise exceptions if any

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