""" import crt.sh findings
"""

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


"""
[{'templateId': 'ssl-issuer', 'host': 'donnad.it', 'vulnerabilityName': 'Detect SSL Certificate Issuer', 'vulnerabilityDetail': '', 'description': "Extract the issuer's organization from the target's certificate. Issuers are entities which sign and distribute certificates.\n", 'type': 'ssl', 'result': ['Corporation Service Company'], 'vulnerableAt': 'donnad.it:443', 'solution': '', 'curl': '', 'severity': 'info', 'tags': ['ssl', 'tls'], 'reference': '', 'cvss-metrics': '', 'cvss-score': None, 'cve-id': '', 'cwe-id': None}, {'templateId': 'ssl-dns-names', 'host': 'donnad.it', 'vulnerabilityName': 'SSL DNS Names', 'vulnerabilityDetail': '', 'description': "Extract the Subject Alternative Name (SAN) from the target's certificate. SAN facilitates the usage of additional hostnames with the same certificate.\n", 'type': 'ssl', 'result': ['donnad.it', 'www.donnad.it'], 'vulnerableAt': 'donnad.it:443', 'solution': '', 'curl': '', 'severity': 'info', 'tags': ['ssl', 'tls'], 'reference': '', 'cvss-metrics': '', 'cvss-score': None, 'cve-id': '', 'cwe-id': None}, {'templateId': 'tls-version', 'host': 'donnad.it', 'vulnerabilityName': 'TLS Version - Detect', 'vulnerabilityDetail': '', 'description': 'TLS version detection is a security process used to determine the version of the Transport Layer Security (TLS) protocol used by a computer or server.\nIt is important to detect the TLS version in order to ensure secure communication between two computers or servers.\n', 'type': 'ssl', 'result': ['tls12'], 'vulnerableAt': 'donnad.it:443', 'solution': '', 'curl': '', 'severity': 'info', 'tags': ['ssl', 'tls'], 'reference': '', 'cvss-metrics': '', 'cvss-score': None, 'cve-id': '', 'cwe-id': None}]
"""


class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def handle(self, *args, **options):
        projects = Project.objects.all()
        for prj in projects:
            print(prj.projectname)
            for ad in prj.activedomain_set.all():
                if ad.monitor is False:
                    continue
                print(ad.value)
                nucleiScanner = Nuclei() # init scanner
                scanResult = nucleiScanner.scan(
                    ad.value,
                    templates=["cves", "misconfiguration", "vulnerabilities"],
                    rateLimit=50,
                    verbose=False,
                    metrics=False,
                    maxHostError=15,
                    stopAfter=None
                )
                print(scanResult)
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
                        'domain': ad,
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
                    f_obj.scan_date = make_aware(datetime.now())
                    f_obj.raw = f
                    f_obj.save()
                # update last scan
                ad.lastscan_time = now()
                ad.save()
