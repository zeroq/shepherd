import subprocess
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware
from datetime import datetime
from project.models import ActiveDomain, Project
from findings.models import Finding


class Command(BaseCommand):
    help = 'Trigger a Nuclei scan against all ActiveDomains domains in a specific project and store the results as Findings objects'

    def add_arguments(self, parser):
        # Add an optional projectid argument
        parser.add_argument(
            '--projectid',
            type=int,
            help='ID of the project to scan',
        )

    def handle(self, *args, **kwargs):
        projectid = kwargs.get('projectid')

        # Fetch active domains based on the project ID
        if projectid:
            try:
                project = Project.objects.get(id=projectid)
                active_domains = ActiveDomain.objects.filter(monitor=True, related_project=project)
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            active_domains = ActiveDomain.objects.filter(monitor=True)

        if not active_domains.exists():
            self.stdout.write("No active domains found to scan.")
            return

        def scan_domain(domain):
            self.stdout.write(f'Scanning domain: {domain.value}')
            try:
                # Create a temporary file to store the Nuclei scan results
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file_path = temp_file.name

                # Trigger Nuclei scan
                result = subprocess.run(['nuclei', '-u', domain.value, '-je', temp_file_path], capture_output=True, text=True)
                if result.returncode != 0:
                    self.stderr.write(f'Error scanning domain {domain.value}: {result.stderr}')
                    return

                # Read the results from the temporary file
                # print(temp_file_path)
                # exit(0)
                with open(temp_file_path, 'r') as file:
                    findings = json.load(file)

                for finding in findings:
                    # Store the result as a Finding object
                    content = {
                        'domain': domain,
                        'domain_name': domain.value,

                        'source': 'nuclei',
                        'name': finding.get('info', {}).get('name', 'Unknown'),
                        'type': finding.get('type', ''),
                        'url': finding.get('url', ''),

                        'description': finding.get('info', {}).get('description', ''),
                        'solution': finding.get('info', {}).get('solution', ''),
                        'reference': finding.get('info', {}).get('reference', ''),

                        'severity': finding.get('info', {}).get('severity', ''),
                        'cve': finding.get('info', {}).get('cve-id', ''),
                        'cvssscore': finding.get('info', {}).get('cvss-score', ''),
                        'cvssmetrics': finding.get('info', {}).get('cvss-metrics', ''),
                        'vulnerableAt': finding.get('info', {}).get('vulnerable_at', ''),
                        'vulnerabilityDetails': finding.get('info', {}).get('details', ''),
                    }
                    finding_obj, _ = Finding.objects.get_or_create(**content)
                    finding_obj.scan_date = make_aware(datetime.now())
                    finding_obj.last_seen = finding_obj.scan_date
                    finding_obj.save()
                domain.lastscan_time = make_aware(datetime.now())
                domain.save()
                if len(findings):
                    self.stdout.write(f'Stored {len(findings)} findings for domain {domain.value}')
            except Exception as e:
                self.stderr.write(f'Exception scanning domain {domain.value}: {str(e)}')

        # Use ThreadPoolExecutor to run scans in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_domain, domain) for domain in active_domains]
            for future in as_completed(futures):
                future.result()  # This will raise any exceptions caught during the scan
