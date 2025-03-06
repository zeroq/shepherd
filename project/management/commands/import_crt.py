""" import crt.sh findings
"""

import sys
import requests
from urllib.parse import urlencode, quote_plus
import json
import dateparser
from datetime import datetime
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

    def handle(self, *args, **options):
        projects = Project.objects.all()
        for prj in projects:
            print(prj.projectname)
            for kw in prj.keyword_set.all():
                if kw.enabled is False:
                    continue
                if kw.ktype not in ['name', 'domain']:
                    continue
                print(kw.keyword)
                url = 'https://crt.sh/?output=json&q=%s' % (kw)
                rsp = requests.get(url)
                try:
                    result = json.loads(rsp.content)
                except:
                    print(rsp.content)
                    sys.exit(255)
                for item in result:
                    #print(json.dumps(item, indent=4))
                    # build top level domain if possible
                    try:
                        parsed_obj = tldextract.extract(item['common_name'])
                    except:
                        continue
                    tld = parsed_obj.domain+"."+parsed_obj.suffix
                    # get unique identifier
                    item_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, "%s" % item['common_name'])
                    # check if item already exists
                    try:
                        sobj = Suggestion.objects.get(uuid=item_uuid)
                        new_object = False
                    except Suggestion.DoesNotExist:
                        new_object = True
                    # ignore existing suggestions
                    if new_object is False:
                        continue
                    # TODO: ignore already monitored entries (table does not exist yet)
                    #
                    # check for wildcard entries
                    if item['common_name'].count('*')>0:
                        wildcard = True
                    else:
                        wildcard = False
                    # check if certificate is still valid
                    before = dateparser.parse(item['not_before'])
                    after = dateparser.parse(item['not_after'])
                    now = datetime.now()
                    valid = False
                    if before<=now<=after:
                        valid = True
                    # prepare suggestion object
                    sugg = {
                        'related_keyword': kw,
                        'related_project': prj,
                        'finding_type': 'certificate',
                        'value': item['common_name'],
                        'uuid': item_uuid,
                        'source': 'crt.sh',
                        'description': item['issuer_name']+'|'+item['name_value'],
                        'creation_time': make_aware(dateparser.parse(item['entry_timestamp'])),
                        'link': '',
                        'cert_valid': valid,
                        'cert_wildcard': wildcard,
                        'raw': item,
                    }
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
                                'finding_type': 'certificate',
                                'finding_subtype': 'domain',
                                'value': tld,
                                'uuid': tld_uuid,
                                'source': 'crt.sh',
                                'description': item['issuer_name']+'|'+item['name_value'],
                                'creation_time': make_aware(dateparser.parse(item['entry_timestamp'])),
                                'link': '',
                                'cert_valid': valid,
                                'cert_wildcard': False,
                                'raw': item,
                            }
                            sobj = Suggestion.objects.create(**sugg)
