import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware
from datetime import datetime
from project.models import ActiveDomain, Project
from findings.models import Screenshot
from django.conf import settings


class Command(BaseCommand):
    help = 'Run Httpx scan against http endpoints'

    def add_arguments(self, parser):
        # Add an optional projectid argument
        parser.add_argument(
            '--projectid',
            type=int,
            help='ID of the project to scan',
        )
        parser.add_argument(
            '--uuids',
            type=str,
            help='Comma separated list of ActiveDomain UUIDs to process',
            required=False,
        )

    def handle(self, *args, **options):
        projectid = options.get('projectid')
        uuids_arg = options.get('uuids')

        if projectid:
            try:
                project = Project.objects.get(id=projectid)
                active_domains = ActiveDomain.objects.filter(monitor=True, related_project=project)
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            active_domains = ActiveDomain.objects.filter(monitor=True)

        # Filter by uuids if provided
        if uuids_arg:
            uuid_list = [u.strip() for u in uuids_arg.split(",") if u.strip()]
            active_domains = active_domains.filter(uuid__in=uuid_list)

        httpx_urls = []
        for active_domain in active_domains:
            active_domain_urls = []
            ports = active_domain.port_set.all()
            self.stdout.write(f"Active Domain: {active_domain.value}")
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
                self.stdout.write(f"  {url}")
            
            httpx_urls += active_domain_urls
        
        httpx_in_file = "/tmp/httpx_urls.txt"
        httpx_out_file = "/tmp/httpx_out.jsonl"
        httpx_path = "/Users/leo.georget/go/bin/httpx"

        with open(httpx_in_file, 'w') as f:
            for url in httpx_urls:
                f.write(f"{url}\n")

        self.stdout.write(f"URLs written to {httpx_in_file}")
        self.stdout.write(f"Total URLs: {len(httpx_urls)}")

        # Execute the httpx command
        command = [
            httpx_path,
            "-l",
            httpx_in_file,
            "-ss",
            "-no-screenshot-full-page",
            "-td",
            "-j",
            "-o",
            httpx_out_file,
        ]

        try:
            result = subprocess.run(command, stdout=subprocess.DEVNULL)
            self.stdout.write("Httpx scan completed successfully.")
            # self.stdout.write(result.stdout)
        except subprocess.CalledProcessError as e:
            self.stdout.write("Error occurred while running Httpx:")
            self.stdout.write(e.stderr)
            return
        
        # Store results in the DB
        with open(httpx_out_file, 'r') as f:
            for line in f:
                # Fields available:
                #     timestamp
                #     port
                #     url !
                #     input
                #     location
                #     title !
                #     scheme
                #     webserver !
                #     content_type
                #     method
                #     host !
                #     path
                #     time
                #     a
                #     tech !
                #     words
                #     lines
                #     status_code !
                #     content_length
                #     failed !
                #     headless_body !
                #     screenshot_bytes !
                #     stored_response_path
                #     screenshot_path
                #     screenshot_path_rel
                #     knowledgebase
                #     resolvers
                screenshot_json = json.loads(line)
                # for key in screenshot_json:
                #     if not key in ['screenshot_bytes', 'headless_body']:
                #         self.stdout.write(f"{key}: {screenshot_json[key]}")
                #     else:
                #         self.stdout.write(f"{key}: AAAAA....")
                # exit(0)
                # Extract domain from url and match to ActiveDomain
                parsed_url = urlparse(screenshot_json["url"])
                domain_value = parsed_url.hostname
                domain_obj = None
                if domain_value:
                    domain_obj = ActiveDomain.objects.filter(value__iexact=domain_value).first()
                    
                screenshot_defaults = {
                    "domain": domain_obj,
                    "technologies": ",".join(screenshot_json["tech"]),
                    "screenshot_base64": screenshot_json["screenshot_bytes"],
                    "title": screenshot_json["title"],
                    "webserver": screenshot_json["webserver"],
                    "host_ip": screenshot_json["host"],
                    "status_code": screenshot_json["status_code"],
                    "response_body": screenshot_json["headless_body"],
                    "failed": screenshot_json["failed"],
                    "date": make_aware(datetime.now())
                }
                # Create or update Screenshot by url
                screenshot_obj, created = Screenshot.objects.update_or_create(
                    url=screenshot_json["url"],
                    defaults=screenshot_defaults,
                )

                self.stdout.write(f"Screenshot saved for url: {screenshot_json['url']}")