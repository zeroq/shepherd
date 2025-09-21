from django.http import HttpResponseForbidden
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.utils.timezone import make_aware
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.conf import settings
from django.utils.html import escape
import uuid as imported_uuid
from project.models import Suggestion, Asset, Project
from jobs.utils import run_job
from suggestions.forms import AddSuggestionForm
import requests
import json
import dateparser
from datetime import datetime
import tldextract
import threading
import csv
from django.http import HttpResponse
from django.contrib.messages import get_messages, add_message, SUCCESS, ERROR

@login_required
def suggestions(request):
    """view all new and open suggestions
    """
    if not request.user.has_perm('project.view_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id'], 'suggestionform': AddSuggestionForm()}
    # check for POST request
    if request.method == 'POST':
        # determine action
        if "btnmonitor" in request.POST:
            if not request.user.has_perm('project.change_suggestion'):
                return HttpResponseForbidden("You do not have permission.")
            action = "monitor"
        elif "btnignore" in request.POST:
            if not request.user.has_perm('project.change_suggestion'):
                return HttpResponseForbidden("You do not have permission.")
            action = "ignore"
        elif "btndelete" in request.POST:
            if not request.user.has_perm('project.delete_suggestion'):
                return HttpResponseForbidden("You do not have permission.")
            action = "delete"
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('suggestions:suggestions'))
        # get UUIDs of items
        id_lst = request.POST.getlist('id[]')
        for item in id_lst:
            if action == "delete":
                try:
                    s_obj = Suggestion.objects.get(uuid=item).delete()
                except Suggestion.DoesNotExist:
                    messages.error(request, 'Unknown Suggestion: %s' % item)
                    continue # take next item
            elif action == "ignore":
                try:
                    s_obj = Suggestion.objects.get(uuid=item)
                    s_obj.ignore = True
                    s_obj.save()
                except Suggestion.DoesNotExist:
                    messages.error(request, 'Unknown Suggestion: %s' % item)
                    continue # take next item
            elif action == "monitor":
                try:
                    s_obj = Suggestion.objects.get(uuid=item)
                except Suggestion.DoesNotExist:
                    messages.error(request, 'Unknown Suggestion: %s' % item)
                    continue # take next item
                if s_obj.finding_type in ['certificate', 'domain']:
                    # check if entry already exists
                    try:
                        m_obj = Asset.objects.get(uuid=s_obj.uuid)
                    except Asset.DoesNotExist:
                        # copy to asset table
                        m_obj = Asset()
                        m_obj.related_keyword = s_obj.related_keyword
                        m_obj.related_project = s_obj.related_project
                        m_obj.value = s_obj.value
                        m_obj.uuid = s_obj.uuid
                        m_obj.source = s_obj.source
                        m_obj.creation_time = s_obj.creation_time
                        m_obj.description = s_obj.description
                        m_obj.link = s_obj.link
                        m_obj.save()
                    # hide from suggestions
                    s_obj.monitor = True
                    s_obj.save()
                    messages.info(request, 'Added %s to the monitoring' % s_obj.value)
                else:
                    messages.error(request, 'Unsupported finding type: %s' % s_obj.finding_type)
                    continue
        # redirect to suggestion list
        return redirect(reverse('suggestions:suggestions'))
    else:
        prj = Project.objects.get(id=request.session['current_project']['prj_id'])
        context['domain_count'] = prj.suggestion_set.filter(finding_type='domain', ignore=False).count()
        context['secondleveldomain_count'] = prj.suggestion_set.filter(finding_type='domain', finding_subtype='domain', ignore=False).count()
        context['starreddomain_count'] = prj.suggestion_set.filter(finding_type='starred_domain', ignore=False).count()
        context['ip_count'] = 0
        context['activetab'] = 'domain'
    return render(request, 'suggestions/list_suggestions.html', context)


@login_required
def manual_add_suggestion(request):
    """Manually add a suggestion with XSS prevention"""
    if not request.user.has_perm('project.add_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    if request.method == 'POST':
        form = AddSuggestionForm(request.POST)
        if form.is_valid():
            record = form.save(commit=False)

            # Sanitize all fields to prevent XSS
            record.value = escape(record.value)
            record.description = escape(record.description) if record.description else None
            record.source = escape(record.source) if record.source else None
            record.link = escape(record.link) if record.link else None

            # Set related_project to currently selected project
            project_id = request.session['current_project']['prj_id']
            record.related_project_id = project_id

            # Generate UUID and save the record
            record.uuid = imported_uuid.uuid5(imported_uuid.NAMESPACE_DNS, "%s" % record.value)
            record.creation_time = timezone.now()
            record.save()

            messages.info(request, "Suggestion successfully added")
        else:
            # Print form errors to the console for debugging
            print(form.errors)
            messages.error(request, "Suggestion failed: %s" % form.errors.as_json(escape_html=False))
    return redirect(reverse('suggestions:suggestions'))


@login_required
def ignored_suggestions(request):
    """view all ignored suggestions
    """
    if not request.user.has_perm('project.view_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    # check for POST request
    if request.method == 'POST':
        # determine action "move" or "delete"
        if "btnmove" in request.POST:
            if not request.user.has_perm('project.change_suggestion'):
                return HttpResponseForbidden("You do not have permission.")
            action = 'move'
        elif "btndelete" in request.POST:
            if not request.user.has_perm('project.delete_suggestion'):
                return HttpResponseForbidden("You do not have permission.")
            action = 'delete'
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('suggestions:ignored_suggestions'))
        # get UUIDs of items
        id_lst = request.POST.getlist('id[]')
        for item in id_lst:
            if action == 'delete':
                try:
                    s_obj = Suggestion.objects.get(uuid=item).delete()
                except Suggestion.DoesNotExist:
                    messages.error(request, 'Unknown Suggestion: %s' % item)
                    continue
            elif action == 'move':
                try:
                    s_obj = Suggestion.objects.get(uuid=item)
                    s_obj.ignore = False
                    s_obj.save()
                except Suggestion.DoesNotExist:
                    messages.error(request, 'Unknown Suggestion: %s' % item)
                    continue
        # redirect to ignore list
        return redirect(reverse('suggestions:ignored_suggestions'))
    return render(request, 'suggestions/list_ignored_suggestions.html', context)

@login_required
def delete_suggestion(request, uuid):
    """remove a suggestion
    """
    if not request.user.has_perm('project.delete_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Suggestion.objects.get(uuid=uuid).delete()
    except Suggestion.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:suggestions'))
    return redirect(reverse('suggestions:suggestions'))

@login_required
def delete_suggestion_ignored(request, uuid):
    """remove a suggestion from ignored view
    """
    if not request.user.has_perm('project.delete_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Suggestion.objects.get(uuid=uuid).delete()
    except Suggestion.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:ignored_suggestions'))
    return redirect(reverse('suggestions:ignored_suggestions'))

@login_required
def monitor_suggestion(request, uuid):
    """move a suggestion to the monitored asset list
    """
    if not request.user.has_perm('project.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Suggestion.objects.get(uuid=uuid)
    except Suggestion.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:suggestions'))
    if s_obj.finding_type in ['certificate', 'domain']:
        # check if entry already exists
        try:
            m_obj = Asset.objects.get(uuid=s_obj.uuid)
        except Asset.DoesNotExist:
            # copy to activedomain table
            m_obj = Asset()
            m_obj.related_keyword = s_obj.related_keyword
            m_obj.related_project = s_obj.related_project
            m_obj.value = s_obj.value
            m_obj.uuid = imported_uuid.uuid5(imported_uuid.NAMESPACE_DNS, "%s" % m_obj.value)
            m_obj.source = s_obj.source
            m_obj.creation_time = s_obj.creation_time
            m_obj.description = s_obj.description
            m_obj.link = s_obj.link
            m_obj.save()
        # hide from suggestions
        s_obj.monitor = True
        s_obj.save()
        messages.info(request, 'Added %s to the monitoring' % s_obj.value)
        return redirect(reverse('suggestions:suggestions'))
    # if nothing matches it is not supported
    messages.error(request, 'Unsupported finding type: %s' % s_obj.finding_type)
    return redirect(reverse('suggestions:suggestions'))

@login_required
def monitor_all_unique_domains_derprecated(request):
    """Monitor all domains that are active and that do not redirect to another domain
    """
    if not request.user.has_perm('project.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    s_objs = Suggestion.objects.filter(redirect_to=None).exclude(active=False).exclude(ignore=True)

    for s_obj in s_objs:
        m_obj, _ = Asset.objects.get_or_create(uuid=s_obj.uuid,
            defaults = {
                "related_keyword": s_obj.related_keyword,
                "related_project": s_obj.related_project,
                "value": s_obj.value,
                "source": s_obj.source,
                "creation_time": s_obj.creation_time,
                "description": s_obj.description,
                "link": s_obj.link,
                "monitor": True,
            }
        )
        # hide from suggestions
        s_obj.monitor = True
        s_obj.save()

    messages.info(request, f"Added {len(s_objs)} domains to the monitoring")
    return redirect(reverse('suggestions:suggestions'))

@login_required
def ignore_suggestion(request, uuid):
    """move suggestion to the ignore list
    """
    if not request.user.has_perm('project.change_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Suggestion.objects.get(uuid=uuid)
    except Suggestion.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:suggestions'))
    s_obj.ignore = True
    s_obj.save()
    return redirect(reverse('suggestions:suggestions'))

@login_required
def reactivate_suggestion(request, uuid):
    """reactivate an ignored suggestion
    """
    if not request.user.has_perm('project.change_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Suggestion.objects.get(uuid=uuid)
    except Suggestion.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:ignored_suggestions'))
    s_obj.ignore = False
    s_obj.save()
    return redirect(reverse('suggestions:ignored_suggestions'))

@login_required
def delete_all_suggestions(request):
    """delete all suggestions in given project
    """
    if not request.user.has_perm('project.delete_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('suggestions:suggestions'))
    # delete all suggestions
    prj_obj.suggestion_set.all().delete()
    return redirect(reverse('suggestions:suggestions'))

@login_required
def update_suggestions(request):
    """update suggestions
    """
    if not request.user.has_perm('project.change_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('suggestions:suggestions'))
    # run keywords of project against crt.sh
    for kw in prj_obj.keyword_set.all():
        if kw.enabled is False:
            continue
        url = 'https://crt.sh/?output=json&q=%s' % (kw)
        rsp = requests.get(url)
        result = json.loads(rsp.content)
        for item in result:
            item_uuid = imported_uuid.uuid5(imported_uuid.NAMESPACE_DNS, "%s" % item['common_name'])
            try:
                sobj = Suggestion.objects.get(uuid=item_uuid)
                new_object = False
            except Suggestion.DoesNotExist:
                new_object = True
            # ignore existing suggestions
            if new_object is False:
                continue
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
                'related_project': prj_obj,
                'finding_type': 'certificate',
                'value': item['common_name'],
                'uuid': item_uuid,
                'source': 'crt.sh',
                'description': item['issuer_name']+'|'+item['name_value'],
                'creation_time': make_aware(dateparser.parse(item['entry_timestamp'])),
                'link': '',
                'cert_valid': valid,
                'cert_wildcard': wildcard
            }
            # create suggestion entry
            sobj = Suggestion.objects.create(**sugg)
    messages.info(request, 'Suggestions Updated successfully')
    return redirect(reverse('suggestions:suggestions'))

@login_required
def upload_suggestions(request):
    if not request.user.has_perm('project.add_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
        
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('suggestions:suggestions'))
    
    if request.method == "POST" and request.FILES.get("domain_file"):
        domain_file = request.FILES["domain_file"]

        # Read all lines into memory (small files) or save to temp file for large files
        lines = [escape(line.decode("utf-8").strip().strip('.')) for line in domain_file]

        def process_domains(lines, prj_obj, user):
            created_cnt = 0
            updated_cnt = 0
            for domain in lines:
                if domain:
                    sugg_defaults = {
                        "related_project": prj_obj,
                        "value": domain,
                        "source": "file_upload",
                        "finding_subtype": "domain",
                        "finding_type": "domain",
                        "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                    }

                    # Check if Starred domain
                    if domain.startswith("*"):
                        sugg_defaults["finding_type"] = "starred_domain"

                    # Check if domain or subdomain
                    parsed_obj = tldextract.extract(domain)
                    if parsed_obj.subdomain:
                        sugg_defaults["finding_subtype"] = 'subdomain'
                    else:
                        sugg_defaults["finding_subtype"] = 'domain'

                    item_uuid = imported_uuid.uuid5(imported_uuid.NAMESPACE_DNS, f"{domain}:{prj_obj.id}")
                    sobj, created = Suggestion.objects.get_or_create(uuid=item_uuid, defaults=sugg_defaults)

                    if created:
                        created_cnt += 1
                    else:
                        if not "file_upload" in sobj.source:
                            sobj.source = sobj.source + ", file_upload"
                        sobj.creation_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                        sobj.save()
                        updated_cnt += 1
            # Optionally, you could log or notify admins here

        # Start processing in a background thread
        thread = threading.Thread(target=process_domains, args=(lines, prj_obj, request.user))
        thread.start()
        messages.success(request, "Domains are being uploaded in the background. Please refresh the page after a while to see the results.")
    else:
        messages.error(request, "No file uploaded.")
    return redirect(reverse('suggestions:suggestions'))


@login_required
def scan_redirects(request):
    if not request.user.has_perm('project.change_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    messages.info(request, 'Domain redirection scan against monitored suggested domains has been triggered in the background. (check jobs)')

    try:
        # Get the project ID from the session
        projectid = context['projectid']

        # Define a function to run the command in a separate thread
        def run_command():
            try:
                # call_command('get_domain_redirect', projectid=projectid)
                command = 'get_domain_redirect'
                args = f'--projectid {projectid}'
                run_job(command, args, projectid, request.user)
            except Exception as e:
                print(f"Error running get_domain_redirect: {e}")

        # Start the thread
        thread = threading.Thread(target=run_command)
        thread.start()

    except Exception as e:
        messages.error(request, f'Error: {e}')
    return redirect(reverse('suggestions:suggestions'))

@login_required
def scan_suggestions(request):
    if not request.user.has_perm('project.change_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    if request.method == 'POST':
        context = {'projectid': request.session['current_project']['prj_id']}
        project_id = context['projectid']

        # Fetch selected UUIDs from POST data (if any)
        selected_uuids = request.POST.getlist('uuid[]')

        def scan_redirect():
            try:
                command = 'get_domain_redirect'
                args = f'--projectid {project_id}'
                if selected_uuids:
                    args += f' --uuids {",".join(selected_uuids)}'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running get_domain_redirect: {e}")

        def monitor_all_unique_domains():
            s_objs = Suggestion.objects.filter(redirect_to=None, related_project__id=project_id, finding_type='domain').exclude(active=False).exclude(ignore=True)

            for s_obj in s_objs:
                m_obj, _ = Asset.objects.get_or_create(uuid=s_obj.uuid,
                    defaults = {
                        "related_keyword": s_obj.related_keyword,
                        "related_project": s_obj.related_project,
                        "value": s_obj.value,
                        "source": s_obj.source,
                        "creation_time": s_obj.creation_time,
                        "description": s_obj.description,
                        "link": s_obj.link,
                        "monitor": True,
                    }
                )
                # hide from suggestions
                s_obj.monitor = True
                s_obj.save()

        def subfinder_scan():
            try:
                command = 'scan_subfinder'
                args = f'--projectid {project_id}'
                if selected_uuids:
                    args += f' --uuids {",".join(selected_uuids)}'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running scan_subfinder: {e}")

        def chained_jobs():
            # Run jobs sequentially: subfinder -> scan for redirection -> monitor not redirecting
            if "subfinder_scan" in request.POST:
                subfinder_scan()
            if "scan_for_redirection" in request.POST:
                scan_redirect()
            if "monitor_not_redirecting" in request.POST:
                monitor_all_unique_domains()
        thread = threading.Thread(target=chained_jobs)
        thread.start()
        messages.info(request, 'Selected actions have been triggered in the background. (check jobs for scans)')

    return redirect(reverse('suggestions:suggestions'))

@login_required
def export_suggestions_csv(request):
    """Export all suggestions for the current project as a CSV file for download."""
    if not request.user.has_perm('project.view_suggestion'):
        return HttpResponseForbidden("You do not have permission.")

    project_id = request.session['current_project']['prj_id']
    suggestions = Suggestion.objects.filter(related_project__id=project_id)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="suggestions.csv"'

    writer = csv.writer(response)
    # Write header
    writer.writerow([
        'UUID', 'Value', 'Related Project', 'Related Keyword', 'Finding Type', 'Finding Subtype',
        'Source', 'Description', 'Link', 'Creation Time', 'Active', 'Ignore', 'Monitor', 'Redirect To'
    ])
    # Write data rows
    for s in suggestions:
        writer.writerow([
            s.uuid,
            s.value,
            s.related_project.projectname if s.related_project else '',
            s.related_keyword.keyword if s.related_keyword else '',
            s.finding_type,
            s.finding_subtype,
            s.source,
            s.description,
            s.link,
            s.creation_time,
            s.active,
            s.ignore,
            s.monitor,
            s.redirect_to,
        ])
    return response
