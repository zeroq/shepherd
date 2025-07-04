from django.core.management.base import BaseCommand
from project.models import Suggestion
import concurrent.futures
import dns.resolver

class Command(BaseCommand):
    help = "Check DNS records for all suggestions and update their active status"

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
            required=False,
        )
        parser.add_argument(
            '--uuids',
            type=str,
            help='Comma separated list of suggestion UUIDs to process',
            required=False,
        )

    def handle(self, *args, **kwargs):
        project_filter = {}
        if kwargs.get('projectid'):
            project_filter['related_project__id'] = kwargs['projectid']

        uuids_arg = kwargs.get('uuids')

        suggestions = Suggestion.objects.filter(**project_filter).filter(finding_type='domain')
        if uuids_arg:
            uuid_list = [u.strip() for u in uuids_arg.split(",") if u.strip()]
            suggestions = suggestions.filter(uuid__in=uuid_list)

        self.stdout.write(f"Checking DNS records for {suggestions.count()} active suggestions...")

        def check_dns(suggestion):
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR']
            try:
                for record_type in record_types:
                    try:
                        dns.resolver.resolve(suggestion.value, record_type)
                        self.stdout.write(f"record found {record_type} for {suggestion.value}")
                        return suggestion, True  # If any record type is resolved, mark as active
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        continue  # Try the next record type
                return suggestion, False  # If no record types are resolved, mark as inactive
            except Exception as e:
                self.stderr.write(f"Error checking {suggestion.value}: {e}")
                return suggestion, suggestion.active  # Keep the current status if an error occurs

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_suggestion = {executor.submit(check_dns, suggestion): suggestion for suggestion in suggestions}
            for future in concurrent.futures.as_completed(future_to_suggestion):
                suggestion, has_dns = future.result()
                print(suggestion.value, has_dns)
                if not has_dns:
                    suggestion.active = False
                    suggestion.save()
                    self.stdout.write(f"Updated {suggestion.value}: active=False")
                else:
                    suggestion.active = True
                    suggestion.save()
                    self.stdout.write(f"Updated {suggestion.value}: active=True")

        self.stdout.write("DNS check completed.")
