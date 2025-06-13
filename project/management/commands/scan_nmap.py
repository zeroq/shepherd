from multiprocessing.pool import ThreadPool
import nmap
import csv
from io import StringIO
from datetime import datetime

from project.models import Project
from findings.models import Port

from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware


"""
['host', 'hostname', 'hostname_type', 'protocol', 'port', 'name', 'state', 'product', 'extrainfo', 'reason', 'version', 'conf', 'cpe']
['3.111.7.95', 'www.tryloctite.in', 'user', 'tcp', '22', 'ssh', 'open', 'OpenSSH', 'Ubuntu Linux; protocol 2.0', 'syn-ack', '8.9p1 Ubuntu 3ubuntu0.7', '10', 'cpe:/o:linux:linux_kernel']
['3.111.7.95', 'ec2-3-111-7-95.ap-south-1.compute.amazonaws.com', 'PTR', 'tcp', '22', 'ssh', 'open', 'OpenSSH', 'Ubuntu Linux; protocol 2.0', 'syn-ack', '8.9p1 Ubuntu 3ubuntu0.7', '10', 'cpe:/o:linux:linux_kernel']
['3.111.7.95', 'www.tryloctite.in', 'user', 'tcp', '80', 'http', 'open', 'nginx', '', 'syn-ack', '', '10', 'cpe:/a:igor_sysoev:nginx']
['3.111.7.95', 'ec2-3-111-7-95.ap-south-1.compute.amazonaws.com', 'PTR', 'tcp', '80', 'http', 'open', 'nginx', '', 'syn-ack', '', '10', 'cpe:/a:igor_sysoev:nginx']
['3.111.7.95', 'www.tryloctite.in', 'user', 'tcp', '443', 'http', 'open', 'nginx', '', 'syn-ack', '', '10', 'cpe:/a:igor_sysoev:nginx']
['3.111.7.95', 'ec2-3-111-7-95.ap-south-1.compute.amazonaws.com', 'PTR', 'tcp', '443', 'http', 'open', 'nginx', '', 'syn-ack', '', '10', 'cpe:/a:igor_sysoev:nginx']
"""

class Command(BaseCommand):
    help = 'Run Nmap scan for active domains in a specific project'

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

        # Get the projects to scan
        if projectid:
            try:
                projects = [Project.objects.get(id=projectid)]
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            projects = Project.objects.all()

        pool = ThreadPool(processes=10)  # Adjust the number of threads as needed

        for prj in projects:
            prj_items = []
            domains_qs = prj.activedomain_set.filter(monitor=True)
            # Filter by uuids if provided
            if uuids_arg:
                uuid_list = [u.strip() for u in uuids_arg.split(",") if u.strip()]
                domains_qs = domains_qs.filter(uuid__in=uuid_list)
            for ad in domains_qs:
                prj_items.append((ad.value, ad))
            # Multi-Process results
            prj_res = pool.map(self.port_lookup, prj_items)
            # Loop through each active domain results
            for entry in prj_res:
                ad_obj = entry[-1]
                port_list = entry[0]
                open_ports_cnt = 0
                for port_entry in port_list:
                    if port_entry["status"] == "open":
                        open_ports_cnt += 1
                        content = {
                            'domain': ad_obj,
                            'port': port_entry['port'],
                        }
                        port_obj, _ = Port.objects.get_or_create(**content)
                        port_obj.domain_name = ad_obj.value
                        port_obj.scan_date = make_aware(datetime.now())
                        port_obj.banner = port_entry['banner']
                        port_obj.status = port_entry['status']
                        port_obj.product = port_entry['product']
                        port_obj.cpe = port_entry['cpe']
                        port_obj.raw = port_entry
                        port_obj.save()
                self.stdout.write(f"[+] {open_ports_cnt} ports found for {ad_obj.value}")

    def port_lookup(self, domain_tuple):
        try:
            webaddress = domain_tuple[0]
            self.stdout.write(f"Nmap scan starting for {webaddress}")
            port_list = []
            nm = nmap.PortScanner()
            nm.scan(
                webaddress,
                arguments='-F -Pn -sC -sV -T4 --version-light',
            )

            f = StringIO(nm.csv())
            r = csv.reader(f, delimiter=';')
            firstRow = None
            for row in r:
                # Skip the first row
                if row[0] == 'host':
                    firstRow = row
                    continue
                new_row = dict(zip(firstRow, row))
                pdict = {
                    'port': int(new_row['port']),
                    'banner': new_row['name'] + '::' + new_row['extrainfo'] + '::' + new_row['version'],
                    'status': new_row['state'],
                    'product': new_row['product'],
                    'cpe': new_row['cpe']
                }
                if pdict not in port_list:
                    port_list.append(pdict)
            return (port_list, domain_tuple[1])
        except Exception as error:
            self.stdout.write(error)