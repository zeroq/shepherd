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

def port_lookup(domain_tuple):
    try:
        webaddress = domain_tuple[0]
        print(webaddress)
        port_list = []
        nm = nmap.PortScanner()
        #nm.scan(webaddress, arguments='-F -PN --proxies socks4://127.0.0.1:9050 -sV --version-light', timeout=30)
        nm.scan(webaddress, arguments='-F -PN -sV --version-light', timeout=40)
        f = StringIO(nm.csv())
        r = csv.reader(f, delimiter=';')
        firstRow = None
        for row in r:
            if row[0] == 'host':
                firstRow = row
                continue  # skip first row
            new_row = dict(zip(firstRow, row))
            pdict = {'port': int(new_row['port']), 'banner': new_row['name']+'::'+new_row['extrainfo']+'::'+new_row['version'], 'status': new_row['state'], 'product': new_row['product'], 'cpe': new_row['cpe']}
            #pdict = {'port': int(row[4]), 'banner': row[5], 'status': row[6], 'product': row[7], 'cpe': row[12]}
            if pdict not in port_list:
                port_list.append(pdict)
        #port_list = list(dict.fromkeys(port_list))
        return(port_list, domain_tuple[1])
    except Exception as error:
        print(error)


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
                if ad.monitor is False:
                    continue
                prj_items.append((ad.value, ad))
            # Multi-Process results
            prj_res = pool.map(port_lookup, prj_items)
            for entry in prj_res:
                d_obj = entry[-1]
                port_list = entry[0]
                for port_entry in port_list:
                    print(port_entry)
                    content = {
                        'domain': d_obj,
                        'port': port_entry['port'],
                        'banner': port_entry['banner'],
                        'status': port_entry['status'],
                        'product': port_entry['product'],
                        'cpe': port_entry['cpe'],
                    }
                    port_obj, created = Port.objects.get_or_create(**content)
                    port_obj.scan_date = make_aware(datetime.now())
                    port_obj.raw = port_entry
                    port_obj.save()
                #print(entry)
                print()

