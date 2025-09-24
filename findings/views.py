import tld
import tldextract
import dateparser
import uuid as imported_uuid
from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import make_aware
from django.utils.html import escape
from django.http import HttpResponseForbidden
from project.models import Project, Asset
from findings.models import Finding, Port, Screenshot
from findings.utils import asset_get_or_create, asset_finding_get_or_create, ignore_asset, ignore_finding
from findings.forms import AddAssetForm
from django.http import JsonResponse
import threading
from jobs.utils import run_job
from django.http import StreamingHttpResponse
import csv


#### Asset stuffs
@login_required
def assets(request):
    # Check if the user has the "view_project" permission or is in the read-only users
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    prj = Project.objects.get(id=context['projectid'])
    
    # Add form for manual asset addition
    context['assetform'] = AddAssetForm()

    # check for POST request
    if request.method == 'POST':
        if not request.user.has_perm('project.change_asset'):
            return HttpResponseForbidden("You do not have permission.")
        # determine action
        if "btnignore" in request.POST:
            action = "ignore"
        elif "btnmove" in request.POST:
            action = "move"
        elif "btndelete" in request.POST:
            action = "delete"
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('findings:assets'))
        # get UUIDs of items
        id_lst = request.POST.getlist('id[]')
        for uuid in id_lst:
            if action == "ignore":
                try:
                    ignore_asset(uuid, prj)
                except Asset.DoesNotExist:
                    messages.error(request, 'Unknown Asset: %s' % uuid)
                    continue # take next item
                messages.info(request, 'Ignored Asset: %s' % Asset.objects.get(uuid=uuid).value)
            elif action == "move":
                try:
                    a_obj = Asset.objects.get(uuid=uuid)
                    # disable monitoring (equivalent to moving back to suggestions)
                    a_obj.monitor = False
                    a_obj.save()
                except Exception as error:
                    messages.error(request, 'Unknown: %s' % error)
                    continue # take next item
                messages.info(request, 'Disabled monitoring for Asset: %s' % a_obj.value)
            elif action == "delete":
                try:
                    a_obj = Asset.objects.get(uuid=uuid)
                    domain_to_delete = a_obj.value
                    a_obj.delete()
                    messages.info(request, 'Deleted Asset: %s' % domain_to_delete)
                except Asset.DoesNotExist:
                    messages.error(request, 'Unknown Asset: %s' % uuid)
                    continue  # take next item
        # redirect to asset list
        return redirect(reverse('findings:assets'))
    else:
        # anything that needs to be done for GET request?
        pass
    return render(request, 'findings/list_assets.html', context)

@login_required
def move_asset(request, uuid):
    """disable monitoring for asset (equivalent to moving back to suggestions)
    """
    if not request.user.has_perm('project.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Exception as error:
        messages.error(request, 'Unknown: %s' % error)
        return redirect(reverse('findings:assets'))
    # disable monitoring
    a_obj.monitor = False
    a_obj.save()
    messages.info(request, f'Disabled monitoring for Asset: {a_obj.value}')
    return redirect(reverse('findings:assets'))

@login_required
def move_all_assets(request):
    """disable monitoring for all assets (equivalent to moving back to suggestions)
    """
    if not request.user.has_perm('project.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('findings:assets'))

    def move_all_assets_task(prj_obj):
        # disable monitoring for all assets
        a_objs = prj_obj.asset_set.filter(monitor=True)
        for a_obj in a_objs:
            a_obj.monitor = False
            a_obj.save()

    # Start processing in a background thread
    thread = threading.Thread(target=move_all_assets_task, args=(prj_obj,))
    thread.start()
    messages.success(request, f"All monitored assets are being disabled in the background. Please refresh the page after a while to see the results.")

    return redirect(reverse('findings:assets'))

@login_required
def ignore_asset_glyphicon(request, uuid):
    """move asset to ignore list
    """
    if not request.user.has_perm('project.change_asset'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    prj = Project.objects.get(id=context['projectid'])
    
    try:
        ignore_asset(uuid, prj)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)

    return redirect(reverse('findings:assets'))

@login_required
def ignore_finding_glyphicon(request, findingid):
    """Toggle finding ignore status (AJAX endpoint)
    """
    if not request.user.has_perm('findings.change_finding'):
        return HttpResponseForbidden("You do not have permission to modify findings.")

    try:
        ignore_finding(findingid)
        return JsonResponse({'success': True, 'message': 'Ignore status toggled successfully.'})
    except Finding.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Unknown Finding: %s' % findingid}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def delete_asset(request, uuid):
    """delete asset completely
    """
    if not request.user.has_perm('project.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Exception as error:
        messages.error(request, 'Unknown: %s' % error)
        return redirect(reverse('findings:assets'))
    # delete the asset completely
    asset_value = a_obj.value
    a_obj.delete()
    messages.info(request, f'Deleted Asset: {asset_value}')
    return redirect(reverse('findings:assets'))

@login_required
def activate_asset(request, uuid):
    """move asset from ignore list back to active asset list
    """
    if not request.user.has_perm('project.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    a_obj.monitor = True
    a_obj.save()
    return redirect(reverse('findings:assets'))

@login_required
def activate_all_assets(request):
    """Move all ignored assets back to active monitoring"""
    if not request.user.has_perm('project.change_asset'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        # Get the current project
        prj_obj = Project.objects.get(id=context['projectid'])
    except Project.DoesNotExist:
        messages.error(request, 'Unknown Project')
        return redirect(reverse('findings:ignored_assets'))

    # Update all ignored assets for the project to set monitor=True
    prj_obj.asset_set.filter(monitor=False).update(monitor=True)

    messages.info(request, 'All ignored assets have been reactivated.')
    return redirect(reverse('findings:assets'))

@login_required
def view_asset(request, uuid):
    """view asset details
    """
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    context = {
        # 'projectid': request.session['current_project']['prj_id'],
        'assetid': uuid,
        'asset': a_obj,
        'info_findings': a_obj.finding_set.filter(
            severity='info',
            # reported=False,
        ),
        'critical_findings': a_obj.finding_set.filter(
            severity='critical',
            # reported=False,
        ),
        'high_findings': a_obj.finding_set.filter(
            severity='high',
            # reported=False,
        ),
        'medium_findings': a_obj.finding_set.filter(
            severity='medium',
            # reported=False,
        ),
        'low_findings': a_obj.finding_set.filter(
            severity='low',
            # reported=False,
        )
    }
    return render(request, 'findings/view_asset.html', context)

@login_required
def view_asset_reported(request, uuid):
    """view asset already reported findings
    """
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    context = {
        'projectid': request.session['current_project']['prj_id'],
        'assetid': uuid,
        'asset': a_obj,
        'info_findings': a_obj.finding_set.filter(
            severity='info',
            reported=True
            ),
        'critical_findings': a_obj.finding_set.filter(
            severity='critical',
            reported=True
            ),
        'high_findings': a_obj.finding_set.filter(
            severity='high',
            reported=True
            ),
        'medium_findings': a_obj.finding_set.filter(
            severity='medium',
            reported=True
            ),
        'low_findings': a_obj.finding_set.filter(
            severity='low',
            reported=True
            )
    }
    return render(request, 'findings/view_asset_reported.html', context)
    

### Nucleus stuffs
@login_required
def send_nucleus(request, findingid):
    """ send the details of the finding to Nucleus
    """
    if not request.user.has_perm('findings.change_finding'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        f_obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        messages.error(request, 'Unknown Finding: %s' % findingid)
        return redirect(reverse('findings:assets'))

    # prepare header
    rheader = {'x-apikey': settings.NUCLEUS_KEY, 'Content-Type': 'application/json'}
    # asset = tld.get_tld(f_obj.domain.value, fix_protocol=True, as_object=True)
    asset_name, asset_id = asset_get_or_create(f_obj.domain.value, settings.NUCLEUS_URL, settings.NUCLEUS_PROJECT, rheader)
    # print(asset_name, asset_id)
    # add finding
    result, msg = asset_finding_get_or_create(asset_name, asset_id, f_obj, settings.NUCLEUS_URL, settings.NUCLEUS_PROJECT, rheader)
    # update reporting time
    f_obj.last_reported = timezone.now()
    f_obj.reported = True
    f_obj.save()

    # Return success response
    return JsonResponse({'success': True, 'message': 'Finding sent to Nucleus successfully.'})


### Nmap stuffs
@login_required
def nmap_results(request):
    if not request.user.has_perm('findings.view_port'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    if request.method == 'POST':
        if 'btndelete' in request.POST:
            if not request.user.has_perm('findings.delete_port'):
                return HttpResponseForbidden("You do not have permission.")

            port_ids = request.POST.getlist('id[]')
            port_objs = Port.objects.filter(id__in=port_ids)
            for port_obj in port_objs:
                port_obj.delete()
            messages.info(request, 'Deleted selected ports')
        else:
            messages.error(request, 'Unknown action received!')
        print(request.POST)
    return render(request, 'findings/list_nmap_results.html', context)


### Scanners stuffs
@login_required
def recent_findings(request):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('projects:projects'))
    # count 
    # severity findings
    five_days = datetime.now() - timedelta(days=settings.RECENT_DAYS) # X days ago
    recent_active_domains = prj_obj.asset_set.all().filter(monitor=True, last_scan_time__gte=make_aware(five_days))
    context['num_info'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, 
    severity='info').count()
    context['num_low'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, 
    severity='low').count()
    context['num_medium'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, 
    severity='medium').count()
    context['num_high'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, 
    severity='high').count()
    context['num_critical'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, 
    severity='critical').count()
    context['past_days'] = settings.RECENT_DAYS
    context['activetab'] = 'critical'
    return render(request, 'findings/list_recent_findings.html', context)

@login_required
def all_findings(request):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}

    if request.method == 'POST':
        # determine action
        if "btndelete" in request.POST:
            if not request.user.has_perm('findings.delete_finding'):
                return HttpResponseForbidden("You do not have permission.")
            action = "delete"
        elif "btnreport" in request.POST:
            if not request.user.has_perm('findings.change_finding'):
                return HttpResponseForbidden("You do not have permission.")
            action = "report"
        elif "btnignore" in request.POST:
            if not request.user.has_perm('findings.change_finding'):
                return HttpResponseForbidden("You do not have permission.")
            action = "ignore"
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('findings:all_findings'))
        # get IDs of items
        id_lst = request.POST.getlist('id[]')

        if action == "delete":
            for findingid in id_lst:
                try:
                    Finding.objects.get(id=findingid).delete()
                except Finding.DoesNotExist:
                    messages.error(request, 'Unknown Finding: %s' % findingid)
                    continue  # take next item
            messages.info(request, 'Selected findings deleted successfully.')

        if action == "report":
            for findingid in id_lst:
                try:
                    send_nucleus(request, findingid)
                except Finding.DoesNotExist:
                    messages.error(request, 'Failed reporting Finding: %s' % findingid)
                    continue  # take next item

        if action == "ignore":
            for findingid in id_lst:
                try:
                    ignore_finding(findingid)
                except Finding.DoesNotExist:
                    messages.error(request, 'Unknown Finding: %s' % findingid)
                    continue  # take next item
            messages.info(request, 'Ignore status toggled for selected findings.')

        return redirect(reverse('findings:all_findings'))
    return render(request, 'findings/list_findings.html', context)

@login_required
def delete_finding(request, uuid, findingid, reported):
    """delete a finding
    """
    if not request.user.has_perm('findings.delete_finding'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    a_obj.finding_set.filter(id=findingid).delete() 
    messages.info(request, 'finding deleted!')
    if reported == 'true':
        return redirect(reverse('findings:view_asset_reported', args=(uuid,)))
    return redirect(reverse('findings:view_asset', args=(uuid,)))

@login_required
def scan_assets(request):
    if not request.user.has_perm('findings.add_finding'):
        return HttpResponseForbidden("You do not have permission.")
    
    if request.method == 'POST':
        context = {'projectid': request.session['current_project']['prj_id']}
        project_id = context['projectid']

        # Fetch selected UUIDs from POST data (if any)
        selected_uuids = request.POST.getlist('uuid[]')
        scan_new_assets = request.POST.get('scan_new_assets') == 'on'
        print('selected_uuids:', selected_uuids)
        print('scan_new_assets:', scan_new_assets)

        # If scan_new_assets is set, override selected_uuids with all new asset UUIDs
        if scan_new_assets:
            new_assets = Asset.objects.filter(related_project=project_id, last_scan_time__isnull=True)
            selected_uuids = list(new_assets.values_list('uuid', flat=True))

        def scan_nmap():
            try:
                command = 'scan_nmap'
                args = f'--projectid {project_id}'
                if selected_uuids:
                    args += f' --uuids {",".join(selected_uuids)}'
                if scan_new_assets:
                    args += ' --new-assets'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running scan_nmap: {e}")

        def scan_httpx():
            try:
                command = 'scan_httpx'
                args = f'--projectid {project_id}'
                if selected_uuids:
                    args += f' --uuids {",".join(selected_uuids)}'
                if scan_new_assets:
                    args += ' --new-assets'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running scan_httpx: {e}")

        def scan_nuclei():
            try:
                command = 'scan_nuclei'
                args = f'--projectid {project_id}'
                if selected_uuids:
                    args += f' --uuids {",".join(selected_uuids)}'
                if scan_new_assets:
                    args += ' --new-assets'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running scan_nuclei: {e}")

        def scan_nuclei_nt():
            try:
                command = 'scan_nuclei'
                args = f'--projectid {project_id} --nt'
                if selected_uuids:
                    args += f' --uuids {",".join(selected_uuids)}'
                if scan_new_assets:
                    args += ' --new-assets'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running scan_nuclei: {e}")

        # Prepare threads for parallel jobs
        threads = []

        # If both scan_nmap and scan_httpx are selected, run them sequentially in a single thread
        if "scan_nmap" in request.POST and "scan_httpx" in request.POST:
            def chained_jobs():
                scan_nmap()
                scan_httpx()
            threads.append(threading.Thread(target=chained_jobs))
            messages.info(request, 'Nmap scan followed by a Httpx scan have been triggered in the background. (check jobs)')
        else:
            if "scan_nmap" in request.POST:
                threads.append(threading.Thread(target=scan_nmap))
                messages.info(request, 'Nmap scan has been triggered in the background. (check jobs)')
            if "scan_httpx" in request.POST:
                threads.append(threading.Thread(target=scan_httpx))
                messages.info(request, 'Httpx scan has been triggered in the background. (check jobs)')

        # Nuclei scans can always be parallelized
        if "scan_nuclei" in request.POST:
            if "scan_nuclei_new_templates" in request.POST:
                threads.append(threading.Thread(target=scan_nuclei_nt))
                messages.info(request, 'Nuclei scan for new templates has been triggered in the background. (check jobs)')
            else:
                threads.append(threading.Thread(target=scan_nuclei))
                messages.info(request, 'Nuclei scan has been triggered in the background. (check jobs)')

        # Start all threads
        for thread in threads:
            thread.start()

    return redirect(reverse('findings:assets'))

@login_required
def httpx_results(request):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")
    context = {
        'projectid': request.session.get('current_project', {}).get('prj_id', None),
    }

    return render(request, 'findings/list_httpx_results.html', context)

@login_required
def export_technologies_csv(request):
    """Export all Screenshot objects as CSV with technologies info."""
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")

    # Get current project id from session
    projectid = request.session.get('current_project', {}).get('prj_id', None)
    if not projectid:
        return HttpResponseForbidden("No project selected.")
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return HttpResponseForbidden("Project does not exist.")

    # Get all screenshots for the project
    domains = prj.asset_set.all()
    screenshots = Port.objects.none()    
    screenshots = Screenshot.objects.filter(domain__in=domains).order_by('-date')

    # Prepare CSV response
    def screenshot_row(s):
        return [
            s.url,
            s.technologies,
            s.title,
            s.status_code,
            s.webserver,
            s.date.strftime('%Y-%m-%d %H:%M:%S') if s.date else '',
        ]

    class Echo:
        def write(self, value):
            return value

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)
    header = ['URL', 'Technologies', 'Title', 'Status Code', 'Webserver', 'Date']
    rows = (screenshot_row(s) for s in screenshots)
    response = StreamingHttpResponse(
        (writer.writerow(row) for row in ([header] + list(rows))),
        content_type="text/csv"
    )
    response['Content-Disposition'] = 'attachment; filename="httpx_technologies.csv"'
    return response

@login_required
def data_leaks(request):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}

    if request.method == 'POST':
        # determine action
        if "btndelete" in request.POST:
            if not request.user.has_perm('findings.delete_finding'):
                return HttpResponseForbidden("You do not have permission.")
            action = "delete"
        elif "btnignore" in request.POST:
            if not request.user.has_perm('findings.change_finding'):
                return HttpResponseForbidden("You do not have permission.")
            action = "ignore"
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('findings:data_leaks'))
        # get IDs of items
        id_lst = request.POST.getlist('id[]')

        if action == "delete":
            for findingid in id_lst:
                try:
                    Finding.objects.get(id=findingid).delete()
                except Finding.DoesNotExist:
                    messages.error(request, 'Unknown Finding: %s' % findingid)
                    continue  # take next item
            messages.info(request, 'Selected findings deleted successfully.')

        if action == "ignore":
            for findingid in id_lst:
                try:
                    ignore_finding(findingid)
                except Finding.DoesNotExist:
                    messages.error(request, 'Unknown Finding: %s' % findingid)
                    continue  # take next item
            messages.info(request, 'Ignore status toggled for selected findings.')

    return render(request, 'findings/list_data_leaks.html', context)


@login_required
def manual_add_asset(request):
    """Manually add an asset with XSS prevention"""
    if not request.user.has_perm('project.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    if request.method == 'POST':
        form = AddAssetForm(request.POST)
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

            # Set scope to external for assets created from suggestions
            record.scope = 'external'
            
            # Set monitor to True for assets (unlike suggestions which are False by default)
            record.monitor = True

            # Generate UUID and save the record
            record.uuid = str(imported_uuid.uuid5(imported_uuid.NAMESPACE_DNS, f"{record.value}:{project_id}"))
            print(record.uuid)
            record.creation_time = timezone.now()
            
            # Ensure redirects_to is explicitly None to avoid foreign key issues
            record.redirects_to = None
            
            # Use force_insert to avoid potential update conflicts
            record.save(force_insert=True)

            messages.info(request, "Asset successfully added")
        else:
            # Print form errors to the console for debugging
            print(form.errors)
            messages.error(request, "Asset failed: %s" % form.errors.as_json(escape_html=False))
    return redirect(reverse('findings:assets'))


@login_required
def upload_assets(request):
    if not request.user.has_perm('project.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
        
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('findings:assets'))
    
    if request.method == "POST" and request.FILES.get("domain_file"):
        domain_file = request.FILES["domain_file"]

        # Read all lines into memory (small files) or save to temp file for large files
        lines = [escape(line.decode("utf-8").strip().strip('.')) for line in domain_file]

        def process_domains(lines, prj_obj, user):
            created_cnt = 0
            updated_cnt = 0
            for domain in lines:
                if domain:
                    asset_defaults = {
                        "related_project": prj_obj,
                        "value": domain,
                        "source": "file_upload",
                        "subtype": "domain",
                        "type": "domain",
                        "scope": "external",
                        "monitor": True,  # Set to True for assets (unlike suggestions)
                        "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                    }

                    # Check if Starred domain
                    if domain.startswith("*"):
                        asset_defaults["type"] = "starred_domain"

                    # Check if domain or subdomain
                    parsed_obj = tldextract.extract(domain)
                    if parsed_obj.subdomain:
                        asset_defaults["subtype"] = 'subdomain'
                    else:
                        asset_defaults["subtype"] = 'domain'

                    item_uuid = imported_uuid.uuid5(imported_uuid.NAMESPACE_DNS, f"{domain}:{prj_obj.id}")
                    sobj, created = Asset.objects.get_or_create(uuid=item_uuid, defaults=asset_defaults)

                    if created:
                        created_cnt += 1
                    else:
                        if not "file_upload" in sobj.source:
                            sobj.source = sobj.source + ", file_upload"
                        sobj.creation_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                        # Ensure assets are monitored (unlike suggestions)
                        sobj.monitor = True
                        sobj.save()
                        updated_cnt += 1
            # Optionally, you could log or notify admins here

        # Start processing in a background thread
        thread = threading.Thread(target=process_domains, args=(lines, prj_obj, request.user))
        thread.start()
        messages.success(request, "Domains are being uploaded in the background. Please refresh the page after a while to see the results.")
    else:
        messages.error(request, "No file provided or invalid request method.")

    return redirect(reverse('findings:assets'))
