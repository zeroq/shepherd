"""check open ports """


from multiprocessing.pool import ThreadPool
import json
import nmap
import csv
from io import StringIO
from datetime import datetime

from project.models import Project, Keyword, Suggestion
from findings.models import Port

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.conf import settings
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
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def handle(self, *args, **options):
        pool = ThreadPool(processes=10)  # increasing this number may speed things up
        # domains that are being monitored
        projects = Project.objects.all()
        for prj in projects:
            prj_items = []
            for ad in prj.activedomain_set.all():
                if ad.monitor:
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
                print("[+] {} ports found for {}".format(open_ports_cnt, ad_obj.value))

    def port_lookup(self, domain_tuple):
        try:
            webaddress = domain_tuple[0]
            print(webaddress)
            port_list = []
            nm = nmap.PortScanner()
            #nm.scan(webaddress, arguments='-F -PN --proxies socks4://127.0.0.1:9050 -sV --version-light', timeout=30)
            # nm.scan(webaddress, arguments='-F -PN -sV --version-light', timeout=40)
            nm.scan(webaddress, arguments='-Pn -sC -sV -T4 -p 80,443,13337 --version-light', 
                    # timeout=40,
                    )

            f = StringIO(nm.csv())
            r = csv.reader(f, delimiter=';')
            firstRow = None
            for row in r:
                # skip first row
                if row[0] == 'host':
                    firstRow = row
                    continue
                new_row = dict(zip(firstRow, row))
                pdict = {
                    'port': int(new_row['port']),
                    'banner': new_row['name']+'::'+new_row['extrainfo']+'::'+new_row['version'],
                    'status': new_row['state'],
                    'product': new_row['product'],
                    'cpe': new_row['cpe']
                }
                #pdict = {'port': int(row[4]), 'banner': row[5], 'status': row[6], 'product': row[7], 'cpe': row[12]}
                if pdict not in port_list:
                    port_list.append(pdict)
            #port_list = list(dict.fromkeys(port_list))
            return(port_list, domain_tuple[1])
        except Exception as error:
            print(error)