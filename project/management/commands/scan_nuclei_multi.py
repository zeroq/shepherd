""" import crt.sh findings
"""

from multiprocessing.pool import ThreadPool
import sys
import requests
from urllib.parse import urlencode, quote_plus
import json
import dateparser
from datetime import datetime
import uuid
from PyNuclei import Nuclei

from project.models import Project, Keyword, Suggestion, ActiveDomain
from findings.models import Finding

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.conf import settings
from django.utils.timezone import make_aware, now

def run_nuclei(domain_tuple):
    webaddress = domain_tuple[0]
    nucleiScanner = Nuclei() # init scanner
    scanResult = nucleiScanner.scan(
        webaddress,
        templates=["cves", "vulnerabilities", "xss", "misconfiguration", "exposed-panels", "detection", "ssl", "network"], # misconfiguration, default-logins, exposed-panels, xss
        rateLimit=50,
        verbose=False,
        metrics=False,
        maxHostError=15,
        stopAfter=None
    )
    #print(scanResult)
    return (scanResult, domain_tuple[1])

class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def handle(self, *args, **options):
        pool = ThreadPool(processes=2)
        projects = Project.objects.all()
        for prj in projects:
            #print(prj.projectname)
            prj_items = []
            for ad in prj.activedomain_set.all():
                if ad.monitor is False:
                    continue
                #print('\t'+ad.value)
                prj_items.append((ad.value, ad))
            # Multi-Process results
            prj_res = pool.map(run_nuclei, prj_items)
            for scanResultTuple in prj_res:
                scanResult = scanResultTuple[0]
                domainObject = scanResultTuple[1]
                for f in scanResult:
                    try:
                        cveid = f['cve-id'][0]
                    except:
                        cveid = ''
                    if f['cvss-score'] is None:
                        score = ''
                    else:
                        score = f['cvss-score']
                    fobj = {
                        'domain': domainObject,
                        'vulnname': f['vulnerabilityName'],
                        'description':  f['description'],
                        'severity': f['severity'],
                        'reference': f['reference'],
                        'source': 'nuclei',
                        'cvssscore': score,
                        'cveid': cveid,
                        'cvssmetrics': f['cvss-metrics'],
                        'solution': f['solution'],
                        'vulnerableAt': f['vulnerableAt'],
                        'vulnerabilityDetails': f['vulnerabilityDetail'],
                    }
                    f_obj, created = Finding.objects.get_or_create(**fobj)
                    # update scan date
                    f_obj.scan_date = make_aware(datetime.now())
                    f_obj.raw = f
                    f_obj.save()
                # update last scan
                domainObject.lastscan_time = now()
                domainObject.save()
