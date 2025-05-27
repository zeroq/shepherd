import tld
from datetime import datetime, timedelta

from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.db.models import Count
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import make_aware
from django.http import HttpResponseForbidden

from project.models import Project, Suggestion, ActiveDomain, Job
from findings.models import Finding, Port
from findings.utils import asset_get_or_create, asset_finding_get_or_create, ignore_asset
from django.core.management import call_command
from django.http import JsonResponse
import threading
from jobs.utils import run_job




#### Asset stuffs
@login_required
def assets(request):
    # Check if the user has the "view_project" permission or is in the read-only users
    if not request.user.has_perm('project.view_activedomain'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    # check for POST request
    if request.method == 'POST':
        if not request.user.has_perm('project.change_activedomain'):
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
                    ignore_asset(uuid)
                except ActiveDomain.DoesNotExist:
                    messages.error(request, 'Unknown Asset: %s' % uuid)
                    continue # take next item
                messages.info(request, 'Ignored Asset: %s' % ActiveDomain.objects.get(uuid=uuid).value)
            elif action == "move":
                try:
                    s_obj = Suggestion.objects.get(uuid=uuid)
                    a_obj = ActiveDomain.objects.get(uuid=uuid)
                    # disable monitoring
                    s_obj.monitor = False
                    s_obj.save()
                    # delete active entry
                    a_obj.delete()
                except Exception as error:
                    messages.error(request, 'Unknown: %s' % error)
                    continue # take next item
                messages.info(request, 'Moved Asset back to suggestions: %s' % s_obj.value)
            elif action == "delete":
                try:
                    a_obj = ActiveDomain.objects.get(uuid=uuid)
                    domain_to_delete = a_obj.value
                    a_obj.delete()
                    messages.info(request, 'Deleted Asset: %s' % domain_to_delete)
                except ActiveDomain.DoesNotExist:
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
    """move asset to suggestions
    """
    if not request.user.has_perm('project.change_activedomain'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Suggestion.objects.get(uuid=uuid)
        a_obj = ActiveDomain.objects.get(uuid=uuid)
    except Exception as error:
        messages.error(request, 'Unknown: %s' % error)
        return redirect(reverse('findings:assets'))
    # disable monitoring
    s_obj.monitor = False
    s_obj.save()
    # delete active entry
    a_obj.delete()
    return redirect(reverse('findings:assets'))

@login_required
def move_all_assets(request):
    """move all assets back to suggestions
    """
    if not request.user.has_perm('project.change_activedomain'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('findings:assets'))
    # disable monitoring
    a_objs = prj_obj.activedomain_set.all()
    for a_obj in a_objs:
        s_obj = Suggestion.objects.get(uuid=a_obj.uuid)
        s_obj.monitor = False
        s_obj.save()
        # delete active entry
        a_obj.delete()

    messages.info(request, f'{len(a_objs)} assets moved back to suggestions')
    return redirect(reverse('findings:assets'))

@login_required
def ignore_asset_glyphicon(request, uuid):
    """move asset to ignore list
    """
    if not request.user.has_perm('project.change_activedomain'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        ignore_asset(uuid)
    except ActiveDomain.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)

    return redirect(reverse('findings:assets'))

@login_required
def delete_asset(request, uuid):
    """delete asset from monitoring (still in suggestions)
    """
    if not request.user.has_perm('project.delete_activedomain'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Suggestion.objects.get(uuid=uuid)
        a_obj = ActiveDomain.objects.get(uuid=uuid)
    except Exception as error:
        messages.error(request, 'Unknown: %s' % error)
        return redirect(reverse('findings:assets'))
    # disable monitoring
    s_obj.monitor = False
    s_obj.save()
    # delete active entry
    a_obj.delete()
    return redirect(reverse('findings:assets'))

@login_required
def activate_asset(request, uuid):
    """move asset from ignore list back to active asset list
    """
    if not request.user.has_perm('project.change_activedomain'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = ActiveDomain.objects.get(uuid=uuid)
    except ActiveDomain.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    a_obj.monitor = True
    a_obj.save()
    return redirect(reverse('findings:assets'))

@login_required
def activate_all_assets(request):
    """Move all ignored assets back to active monitoring"""
    if not request.user.has_perm('project.change_activedomain'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        # Get the current project
        prj_obj = Project.objects.get(id=context['projectid'])
    except Project.DoesNotExist:
        messages.error(request, 'Unknown Project')
        return redirect(reverse('findings:ignored_assets'))

    # Update all ignored assets for the project to set monitor=True
    prj_obj.activedomain_set.filter(monitor=False).update(monitor=True)

    messages.info(request, 'All ignored assets have been reactivated.')
    return redirect(reverse('findings:assets'))

@login_required
def view_asset(request, uuid):
    """view asset details
    """
    if not request.user.has_perm('project.view_activedomain'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = ActiveDomain.objects.get(uuid=uuid)
    except ActiveDomain.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    context = {
        'projectid': request.session['current_project']['prj_id'],
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
    if not request.user.has_perm('project.view_activedomain'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = ActiveDomain.objects.get(uuid=uuid)
    except ActiveDomain.DoesNotExist:
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
def send_nucleus(request, uuid, findingid):
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
    asset = tld.get_tld(f_obj.domain.value, fix_protocol=True, as_object=True)
    asset_name, asset_id = asset_get_or_create(asset.fld, settings.NUCLEUS_URL, settings.NUCLEUS_PROJECT, rheader)
    print(asset_name, asset_id)
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
    recent_active_domains = prj_obj.activedomain_set.all().filter(monitor=True, lastscan_time__gte=make_aware(five_days))
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
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('findings:all_findings'))
        # get IDs of items
        id_lst = request.POST.getlist('id[]')
        for item in id_lst:
            if action == "delete":
                try:
                    Finding.objects.get(id=item).delete()
                except Finding.DoesNotExist:
                    messages.error(request, 'Unknown Finding: %s' % item)
                    continue  # take next item
        messages.info(request, 'Selected findings deleted successfully.')
        return redirect(reverse('findings:all_findings'))
    return render(request, 'findings/list_findings.html', context)

@login_required
def delete_finding(request, uuid, findingid, reported):
    """delete a finding
    """
    if not request.user.has_perm('findings.delete_finding'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = ActiveDomain.objects.get(uuid=uuid)
    except ActiveDomain.DoesNotExist:
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

        def scan_nmap():
            try:
                command = 'scan_nmap'
                args = f'--projectid {project_id}'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running test_job: {e}")

        def scan_gowitness():
            try:
                command = 'scan_gowitness'
                args = f'--projectid {project_id}'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running test_job: {e}")

        def scan_nuclei():
            try:
                command = 'scan_nuclei'
                args = f'--projectid {project_id}'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running test_job: {e}")

        def scan_nuclei_nt():
            try:
                command = 'scan_nuclei'
                args = f'--projectid {project_id} --nt'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running test_job: {e}")

        if "scan_nmap" in request.POST and "scan_gowitness" in request.POST:
            # Run test_job, then test_job2 after it finishes
            def chained_jobs():
                scan_nmap()
                scan_gowitness()
            thread = threading.Thread(target=chained_jobs)
            thread.start()
            messages.info(request, 'Nmap scan followed by a GoWitness scan have been triggered in the background. (check jobs)')
        elif "scan_gowitness" in request.POST:
            thread = threading.Thread(target=scan_gowitness)
            thread.start()
            messages.info(request, 'GoWitness scan has been triggered in the background. (check jobs)')
        elif "scan_nmap" in request.POST:
            thread = threading.Thread(target=scan_nmap)
            thread.start()
            messages.info(request, 'Nmap scan has been triggered in the background. (check jobs)')

        if "scan_nuclei" in request.POST:
            if "scan_nuclei_new_templates" in request.POST:
                thread = threading.Thread(target=scan_nuclei_nt)
                thread.start()
                messages.info(request, 'Nuclei scan for new templates has been triggered in the background. (check jobs)')
            else:
                thread = threading.Thread(target=scan_nuclei)
                thread.start()
                messages.info(request, 'Nuclei scan has been triggered in the background. (check jobs)')

    return redirect(reverse('findings:assets'))