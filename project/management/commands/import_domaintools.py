import hmac
import hashlib
import sys
import time
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
        total_suggestion_count = 0
        uri = "/v1/iris-investigate/"
        host = "api.domaintools.com"

        projects = Project.objects.all()
        for prj in projects:
            print(prj.projectname)
            for kw in prj.keyword_set.all():

                if not kw.enabled:
                    continue

                if kw.ktype == "registrant_org":
                    # Per registrant
                    print("[+] domaintools search per registrant: {}".format(kw.keyword))
                    params_get = {
                        "api_username" : settings.DOMAINTOOLS_USER,
                        "registrant" : kw.keyword,
                    }
                    suggestion_count = self.domaintools_suggestion_population(host, uri, params_get, kw, prj)
                    print("[+] suggestions populated: {}".format(suggestion_count))
                    total_suggestion_count += suggestion_count

                    # Per registrant org
                    print("[+] domaintools search per registrant organization: {}".format(kw.keyword))
                    params_get = {
                        "api_username" : settings.DOMAINTOOLS_USER,
                        "registrant_org" : kw.keyword,
                    }
                    suggestion_count = self.domaintools_suggestion_population(host, uri, params_get, kw, prj)
                    print("[+] suggestions populated: {}".format(suggestion_count))
                    total_suggestion_count += suggestion_count

                if kw.ktype == "registrant_email":
                    # Per e-mail
                    print("[+] domaintools search per registrant email: {}".format(kw.keyword))
                    params_get = {
                        "api_username" : settings.DOMAINTOOLS_USER,
                        "email" : kw.keyword,
                    }
                    suggestion_count = self.domaintools_suggestion_population(host, uri, params_get, kw, prj)
                    print("[+] suggestions populated: {}".format(suggestion_count))
                    total_suggestion_count += suggestion_count

                if kw.ktype == "registrant_email_domain":
                    # Per e-mail domain
                    print("[+] domaintools search per registrant email domain: {}".format(kw.keyword))
                    params_get = {
                        "api_username" : settings.DOMAINTOOLS_USER,
                        "email_domain" : kw.keyword,
                    }
                    suggestion_count = self.domaintools_suggestion_population(host, uri, params_get, kw, prj)
                    print("[+] suggestions populated: {}".format(suggestion_count))
                    total_suggestion_count += suggestion_count

                else:
                    continue

        print("[+] total domaintools suggestions populated or updated: {}".format(total_suggestion_count))


    def domaintools_suggestion_population(self, host, uri, params_get, kw, prj):

        # API authentication: signature
        url = "https://{0}{1}".format(host, uri)
        ts = self.timestamp()
        signature = self.sign(ts, uri)
        params_get["timestamp"] = ts
        params_get["signature"] = signature

        # Debug
        proxies = {}
        verify = True
        # if settings.DEBUG:
        #     proxies["https"] = "http://127.0.0.1:8080"
        #     verify = False

        # Error count
        err_cnt = 0
        err_limit = 5

        # Suugesstion count
        suggestion_count = 0

        rsp = requests.get(url, params=params_get, proxies=proxies, verify=verify)
        result = json.loads(rsp.content)

        # Initialize list of items that will conatin doaintools results
        items = []
        if result["response"]["limit_exceeded"]:
            print("[-] domaintools results limit exceeded -> refine the query")
            return suggestion_count
        else:
            items += result['response']['results']
            while result['response']['has_more_results']:
                try:
                    params_get["position"] = result["response"]["position"]
                    rsp = requests.get(url, params=params_get, proxies=proxies, verify=verify)
                    result = json.loads(rsp.content)
                    # Add results of the next pages
                    items += result['response']['results']
                    err_cnt = 0
                except:
                    print("[-] request failed: {}, {}. Waiting 1 sec..".format(rsp, rsp.text))
                    time.sleep(0.5)
                    if err_cnt >= err_limit:
                        print("[-] Too many failed requests, skip method")
                        break
                    else:
                        err_cnt += 1
        
        # Process the results and add them to the database        
        for item in items:
            
            # get unique identifier
            domain = item['domain']
            item_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, str(domain))
            description_list = []
            if item['registrant_org']['value']:
                description_list.append("Registrant Org: {}".format(item['registrant_org']['value']))
            if item['registrant_contact']['email']:
                emails = []
                for email in item['registrant_contact']['email']:
                    emails.append(email['value'])
                description_list.append("Registrant Emails: {}".format(", ".join(emails)))
            description = ", ".join(description_list)
            sugg = {
                'related_keyword': kw,
                'related_project': prj,
                'finding_type': 'domain',
                'value': domain,
                'active': str(item['active']),
                'uuid': item_uuid,
                'source': 'domaintools',
                'description': description,
                'link': '',
                'raw': item,
            }
            try:
                sugg['creation_time'] = make_aware(dateparser.parse(item['first_seen']['value']))
            except:
                sugg['creation_time'] = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
            # check if domain or subdomain
            parsed_obj = tldextract.extract(domain)
            if len(parsed_obj.subdomain) == 0:
                sugg['finding_subtype'] = 'domain'
            else:
                sugg['finding_subtype'] = 'subdomain'
            # create suggestion entry
            sobj, created = Suggestion.objects.update_or_create(uuid=item_uuid, defaults=sugg)
            suggestion_count += 1

            # check if TLD is already in our database
            # tld
            tld = parsed_obj.domain+"."+parsed_obj.suffix
            if len(parsed_obj.subdomain) > 0:
                tld_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, tld)

                # Modify suggestion object
                sugg['uuid'] = tld_uuid
                sugg['value'] = tld
                sugg['finding_subtype'] = 'domain'

                # Add active status
                if item['active']:
                    sugg['active'] = 'True'

                # create suggestion entry
                sobj, created = Suggestion.objects.update_or_create(uuid=tld_uuid, defaults=sugg)
                suggestion_count += 1

        return suggestion_count
    