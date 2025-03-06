"""check open ports """

import sys
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

    def add_arguments(self, parser):
        parser.add_argument("project", nargs="+", type=str)
        parser.add_argument("filename", nargs="+", type=str)

    def handle(self, *args, **options):
        # select the proper project
        prjname = options['project'][0]
        try:
            prj = Project.objects.get(projectname=str(prjname))
        except Project.DoesNotExist:
            print("Given Project does not exist!")
            projects = Project.objects.all()
            for prj in projects:
                print(prj.projectname)
            sys.exit(255)
        # just take the first keyword
        kw = prj.keyword_set.first()
        # iterate the given file
        for fn in options['filename']:
            try:
                with open(fn) as fp:
                    for rline in fp:
                        # one domain per line
                        domain = rline.strip()
                        parsed_obj = tldextract.extract(domain)
                        # ExtractResult(subdomain='blah', domain='loctite', suffix='com.br', is_private=False)
                        tld = parsed_obj.domain+"."+parsed_obj.suffix
                        # get unique identifier
                        item_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, "%s" % domain)
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
                            'value': domain,
                            'uuid': item_uuid,
                            'source': 'file',
                            'description': 'Imported from %s' % (fn),
                            'link': '',
                            'raw': domain,
                        }
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
                                    'source': 'file',
                                    'description': 'Imported from %s' % (fn),
                                    'link': '',
                                    'raw': domain,
                                }
                                sugg['creation_time'] = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                                sobj = Suggestion.objects.create(**sugg)
            except Exception as error:
                print(error)
                sys.exit(255)

