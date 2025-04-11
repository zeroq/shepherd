import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware
from datetime import datetime
from project.models import ActiveDomain, Project
from findings.models import Finding
from django.conf import settings


class Command(BaseCommand):
    help = 'Run GoWitness scan against http endpoints'

    def add_arguments(self, parser):
        # Add an optional projectid argument
        parser.add_argument(
            '--projectid',
            type=int,
            help='ID of the project to scan',
        )

    def handle(self, *args, **options):
        projectid = options.get('projectid')

        if projectid:
            try:
                project = Project.objects.get(id=projectid)
                active_domains = ActiveDomain.objects.filter(monitor=True, related_project=project)
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            active_domains = ActiveDomain.objects.filter(monitor=True)

        gowitness_urls = []
        for active_domain in active_domains:
            active_domain_urls = []
            ports = active_domain.port_set.all()
            print(f"Active Domain: {active_domain.value}")
            for port in ports:
                if "https" in port.banner:
                    url = f"https://{active_domain.value}:{port.port}"
                    active_domain_urls.append(url)
                elif "http" in port.banner:
                    active_domain_urls += [
                        f"http://{active_domain.value}:{port.port}",
                        f"https://{active_domain.value}:{port.port}",
                    ]
            active_domain_urls = list(set(active_domain_urls))
            for url in active_domain_urls:
                print(f"  {url}")
            
            gowitness_urls += active_domain_urls
        
        gowitness_file = "/tmp/gowitness_urls.txt"
        with open(gowitness_file, 'w') as f:
            for url in gowitness_urls:
                f.write(f"{url}\n")

        print(f"URLs written to {gowitness_file}")
        print(f"Total URLs: {len(gowitness_urls)}")

        # Execute the gowitness command
        command = [
            "gowitness", "scan", "file",
            "-f", gowitness_file,
            "--threads", "10",
            "--write-db"
        ]

         # Use the GOWITNESS_DB_LOCATION from settings as the working directory
        gowitness_db_location = getattr(settings, 'GOWITNESS_DB_LOCATION', None)
        if not gowitness_db_location:
            raise CommandError("GOWITNESS_DB_LOCATION is not set in settings.py")

        try:
            result = subprocess.run(command, cwd=gowitness_db_location, capture_output=True, text=True, check=True)
            print("GoWitness scan completed successfully.")
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print("Error occurred while running GoWitness:")
            print(e.stderr)
    