""" import crt.sh findings
"""

import hmac
import hashlib
import sys
import requests
from urllib.parse import urlencode, quote_plus
import json
import dateparser
from datetime import datetime, timezone
import uuid
import tldextract

from project.models import Project, Keyword, Suggestion

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.conf import settings
from django.utils.timezone import make_aware



class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def timestamp(self):
        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def sign(self, timestamp, uri):
        params = "".join([settings.DOMAINTOOLS_USER, timestamp, uri])
        return hmac.new(settings.DOMAINTOOLS_KEY.encode("utf-8"), params.encode("utf-8"), digestmod=hashlib.sha1).hexdigest()

    def handle(self, *args, **options):
        uri = "/v1/iris-investigate/"
        host = "api.domaintools.com"
        projects = Project.objects.all()
        for prj in projects:
            print(prj.projectname)
            for kw in prj.keyword_set.all():
                if kw.enabled is False:
                    continue
                if kw.ktype not in ['name']:
                    continue
                print(kw.keyword)
                ts = self.timestamp()
                signature = self.sign(ts, uri)
                url = "https://{0}{1}?registrant_org={5}&api_username={2}&signature={3}&timestamp={4}".format(host, uri, settings.DOMAINTOOLS_USER, signature, ts, quote_plus(kw.keyword))
                #print(url)
                rsp = requests.get(url)
                result = json.loads(rsp.content)
                #print(result)
                # {'response': {'limit_exceeded': False, 'has_more_results': True, 'message': 'There is more data for you to enjoy.', 'results_count': 500, 'total_count': 3360, 'position': '1e067923c508495ab4bef4bdcc2fc6aa', 'results': [], 'missing_domains': []}}
                for item in result['response']['results']:
                    #print(item)
                    domain = item['domain']
                    # tld
                    parsed_obj = tldextract.extract(domain)
                    tld = parsed_obj.domain+"."+parsed_obj.suffix
                    # get unique identifier
                    item_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, "%s" % item['domain'])
                    # check if item already exists
                    try:
                        sobj = Suggestion.objects.get(uuid=item_uuid)
                        new_object = False
                    except Suggestion.DoesNotExist:
                        new_object = True
                    # ignore existing suggestions
                    if new_object is False:
                        continue
                    # prepare suggestion object
                    sugg = {
                        'related_keyword': kw,
                        'related_project': prj,
                        'finding_type': 'domain',
                        'value': item['domain'],
                        'uuid': item_uuid,
                        'source': 'domaintools',
                        'description': 'Registrant Org: %s' % item['registrant_org']['value'],
                        'link': '',
                        'raw': item,
                    }
                    try:
                        sugg['creation_time'] = make_aware(dateparser.parse(item['first_seen']['value']))
                    except:
                        sugg['creation_time'] = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                    # check if domain or subdomain
                    if len(parsed_obj.subdomain) == 0:
                        sugg['finding_subtype'] = 'domain'
                    else:
                        sugg['finding_subtype'] = 'subdomain'
                    # create suggestion entry
                    sobj = Suggestion.objects.create(**sugg)
                    # check if TLD is already in our database
                    if len(parsed_obj.subdomain) > 0:
                        tld_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, "%s" % tld)
                        try:
                            sobj = Suggestion.objects.get(uuid=tld_uuid)
                            new_object = False
                        except Suggestion.DoesNotExist:
                            new_object = True
                        if new_object is True:
                            sugg = {
                                'related_keyword': kw,
                                'related_project': prj,
                                'finding_type': 'domain',
                                'finding_subtype': 'domain',
                                'value': tld,
                                'uuid': tld_uuid,
                                'source': 'domaintools',
                                'description': 'Registrant Org: %s' % item['registrant_org']['value'],
                                'link': '',
                                'raw': item,
                            }
                            try:
                                sugg['creation_time'] = make_aware(dateparser.parse(item['first_seen']['value']))
                            except:
                                sugg['creation_time'] = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                            sobj = Suggestion.objects.create(**sugg)
                while result['response']['has_more_results'] is True:
                    url = "https://{0}{1}?registrant_org={5}&position={6}&api_username={2}&signature={3}&timestamp={4}".format(host, uri, settings.DOMAINTOOLS_USER, signature, ts, quote_plus(kw.keyword), result['response']['position'])
                    rsp = requests.get(url)
                    result = json.loads(rsp.content)
                    for item in result['response']['results']:
                        domain = item['domain']
                        # tld
                        parsed_obj = tldextract.extract(domain)
                        tld = parsed_obj.domain+"."+parsed_obj.suffix
                        # get unique identifier
                        item_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, "%s" % item['domain'])
                        # check if item already exists
                        try:
                            sobj = Suggestion.objects.get(uuid=item_uuid)
                            new_object = False
                        except Suggestion.DoesNotExist:
                            new_object = True
                        # ignore existing suggestions
                        if new_object is False:
                            continue
                        # prepare suggestion object
                        sugg = {
                            'related_keyword': kw,
                            'related_project': prj,
                            'finding_type': 'domain',
                            'value': item['domain'],
                            'uuid': item_uuid,
                            'source': 'domaintools',
                            'description': 'Registrant Org: %s' % item['registrant_org']['value'],
                            'link': '',
                            'raw': item,
                        }
                        try:
                            sugg['creation_time'] = make_aware(dateparser.parse(item['first_seen']['value']))
                        except:
                            sugg['creation_time'] = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                        # check if domain or subdomain
                        if len(parsed_obj.subdomain) == 0:
                            sugg['finding_subtype'] = 'domain'
                        else:
                            sugg['finding_subtype'] = 'subdomain'
                        # create suggestion entry
                        sobj = Suggestion.objects.create(**sugg)
                        # check if TLD is already in our database
                        if len(parsed_obj.subdomain) > 0:
                            tld_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, "%s" % tld)
                            try:
                                sobj = Suggestion.objects.get(uuid=tld_uuid)
                                new_object = False
                            except Suggestion.DoesNotExist:
                                new_object = True
                            if new_object is True:
                                sugg = {
                                    'related_keyword': kw,
                                    'related_project': prj,
                                    'finding_type': 'domain',
                                    'finding_subtype': 'domain',
                                    'value': tld,
                                    'uuid': tld_uuid,
                                    'source': 'domaintools',
                                    'description': 'Registrant Org: %s' % item['registrant_org']['value'],
                                    'link': '',
                                    'raw': item,
                                }
                                try:
                                    sugg['creation_time'] = make_aware(dateparser.parse(item['first_seen']['value']))
                                except:
                                    sugg['creation_time'] = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                                sobj = Suggestion.objects.create(**sugg)
