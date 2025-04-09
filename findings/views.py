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

from project.models import Project, Suggestion, ActiveDomain
from findings.models import Finding, Port
from findings.utils import asset_get_or_create, asset_finding_get_or_create
from django.core.management import call_command
from django.http import JsonResponse
import threading


#### Asset stuffs 
@login_required
def assets(request):
    context = {'projectid': request.session['current_project']['prj_id']}
    # check for POST request
    if request.method == 'POST':
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
        for item in id_lst:
            if action == "ignore":
                try:
                    a_obj = ActiveDomain.objects.get(uuid=item)
                    a_obj.monitor = False
                    a_obj.save()
                except ActiveDomain.DoesNotExist:
                    messages.error(request, 'Unknown Asset: %s' % item)
                    continue # take next item
                messages.info(request, 'Ignored Asset: %s' % a_obj.value)
            elif action == "move":
                try:
                    s_obj = Suggestion.objects.get(uuid=item)
                    a_obj = ActiveDomain.objects.get(uuid=item)
                    # disable monitoring
                    s_obj.monitor = False
                    s_obj.save()
                    # delete active entry
                    a_obj.delete()
                except Exception as error:
                    messages.error(request, 'Unknssown: %s' % error)
                    continue # take next item
                messages.info(request, 'Moved Asset back to suggestions: %s' % s_obj.value)
            elif action == "delete":
                try:
                    a_obj = ActiveDomain.objects.get(uuid=item)
                    domain_to_delete = a_obj.value
                    a_obj.delete()
                    messages.info(request, 'Deleted Asset: %s' % domain_to_delete)
                except ActiveDomain.DoesNotExist:
                    messages.error(request, 'Unknown Asset: %s' % item)
                    continue  # take next item
        # redirect to asset list
        return redirect(reverse('findings:assets'))
    else:
        # anything that needs to be done for GET request?
        pass
    return render(request, 'findings/list_assets.html', context)

@login_required
def ignored_assets(request):
    context = {'projectid': request.session['current_project']['prj_id']}
    # check for POST request
    if request.method == 'POST':
        # determine action
        if "btndelete" in request.POST:
            action = "delete"
        elif "btnmove" in request.POST:
            action = "move"
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('findings:ignored_assets'))
        # get UUIDs of items
        id_lst = request.POST.getlist('id[]')
        for item in id_lst:
            if action == 'delete':
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
                messages.info(request, 'Deleted Asset from monitoring: %s' % s_obj.value)
            elif action == 'move':
                try:
                    a_obj = ActiveDomain.objects.get(uuid=item)
                    a_obj.monitor = True
                    a_obj.save()
                except ActiveDomain.DoesNotExist:
                    messages.error(request, 'Unknown Asset: %s' % uuid)
                    continue # take next item
                messages.info(request, 'Moved Asset back to monitoring: %s' % a_obj.value)
        # redirect to asset list
        return redirect(reverse('findings:ignored_assets'))
    else:
        # anything that needs to be done for GET request?
        pass
    return render(request, 'findings/list_assets_ignored.html', context)

@login_required
def move_asset(request, uuid):
    """move asset to suggestions
    """
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
def ignore_asset(request, uuid):
    """move asset to ignore list
    """
    try:
        a_obj = ActiveDomain.objects.get(uuid=uuid)
    except ActiveDomain.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    a_obj.monitor = False
    a_obj.save()
    return redirect(reverse('findings:assets'))

@login_required
def delete_asset(request, uuid):
    """delete asset from monitoring (still in suggestions)
    """
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
    print("OOOOKKKKKK")
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
    print("OOOOKKKKKK")
    return redirect(reverse('findings:assets'))

@login_required
def view_asset(request, uuid):
    """view asset details
    """
    try:
        a_obj = ActiveDomain.objects.get(uuid=uuid)
    except ActiveDomain.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    context = {
        'projectid': request.session['current_project']['prj_id'],
        'assetid': uuid,
        'asset': a_obj,
        'info_findings': a_obj.finding_set.filter(severity='info', reported=False),
        'critical_findings': a_obj.finding_set.filter(severity='critical', reported=False),
        'high_findings': a_obj.finding_set.filter(severity='high', reported=False),
        'medium_findings': a_obj.finding_set.filter(severity='medium', reported=False),
        'low_findings': a_obj.finding_set.filter(severity='low', reported=False)
    }
    return render(request, 'findings/view_asset.html', context)

@login_required
def view_asset_reported(request, uuid):
    """view asset already reported findings
    """
    try:
        a_obj = ActiveDomain.objects.get(uuid=uuid)
    except ActiveDomain.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    context = {
        'projectid': request.session['current_project']['prj_id'],
        'assetid': uuid,
        'asset': a_obj,
        'info_findings': a_obj.finding_set.filter(severity='info', reported=True),
        'critical_findings': a_obj.finding_set.filter(severity='critical', reported=True),
        'high_findings': a_obj.finding_set.filter(severity='high', reported=True),
        'medium_findings': a_obj.finding_set.filter(severity='medium', reported=True),
        'low_findings': a_obj.finding_set.filter(severity='low', reported=True)
    }
    return render(request, 'findings/view_asset_reported.html', context)
    

### Nucleus stuffs
@login_required
def send_nucleus(request, uuid, findingid):
    """ send the details of the finding to Nucleus
    """
    try:
        f_obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        messages.error(request, 'Unknown Finding: %s' % findingid)
        return redirect(reverse('findings:assets'))
    try:
        a_obj = ActiveDomain.objects.get(uuid=uuid)
    except ActiveDomain.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    # prepare header
    rheader = {'x-apikey': settings.NUCLEUS_KEY, 'Content-Type': 'application/json'}
    asset = tld.get_tld(a_obj.value, fix_protocol=True, as_object=True)
    asset_name, asset_id = asset_get_or_create(asset.fld, settings.NUCLEUS_URL, rheader)
    print(asset_name, asset_id)
    # add finding
    result, msg = asset_finding_get_or_create(asset_id, f_obj, settings.NUCLEUS_URL, rheader)
    # update reporting time
    f_obj.last_reported = timezone.now()
    f_obj.reported = True
    f_obj.save()
    return redirect(reverse('findings:view_asset', args=(uuid,)))


### Nmap stuffs
@login_required
def nmap_results(request):
    context = {'projectid': request.session['current_project']['prj_id']}
    if request.method == 'POST':
        if 'btndelete' in request.POST:
            port_ids = request.POST.getlist('id[]')
            port_objs = Port.objects.filter(id__in=port_ids)
            for port_obj in port_objs:
                port_obj.delete()
            messages.info(request, 'Deleted selected ports')
        else:
            messages.error(request, 'Unknown action received!')
        print(request.POST)
    return render(request, 'findings/list_nmap_results.html', context)

@login_required
def nmap_scan(request):
    context = {'projectid': request.session['current_project']['prj_id']}
    messages.info(request, 'Nmap scan against monitored hosts triggered in the background.')
    try:
        # Get the project ID from the session
        projectid = context['projectid']

        # Define a function to run the command in a separate thread
        def run_command():
            try:
                call_command('scan_nmap', projectid=projectid)
            except Exception as e:
                print(f"Error running scan_nmap: {e}")

        # Start the thread
        thread = threading.Thread(target=run_command)
        thread.start()

    except Exception as e:
        messages.error(request, f'Error: {e}')
    return render(request, 'findings/list_assets.html', context)

### Scanners stuffs
@login_required
def recent_findings(request):
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('projects:projects'))
    # count severity findings
    five_days = datetime.now() - timedelta(days=settings.RECENT_DAYS) # X days ago
    recent_active_domains = prj_obj.activedomain_set.all().filter(monitor=True, lastscan_time__gte=make_aware(five_days))
    context['num_info'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, severity='info').count()
    context['num_low'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, severity='low').count()
    context['num_medium'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, severity='medium').count()
    context['num_high'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, severity='high').count()
    context['num_critical'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, severity='critical').count()
    context['past_days'] = settings.RECENT_DAYS
    context['activetab'] = 'critical'
    return render(request, 'findings/list_recent_findings.html', context)

@login_required
def all_findings(request):
    context = {'projectid': request.session['current_project']['prj_id']}
    if request.method == 'POST':
        # determine action
        if "btndelete" in request.POST:
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
def nuclei_scan(request):
    context = {'projectid': request.session['current_project']['prj_id']}

    if request.method == 'GET':
        # determine action
        nt = False
        # Get the project ID from the session
        projectid = context['projectid']
        if "nt" in request.GET:
            nt = True

        try:

            # Define a function to run the command in a separate thread
            def run_command():
                try:
                    call_command("scan_nuclei", nt=nt, projectid=projectid)
                except Exception as e:
                    print(f"Error running scan_nuclei: {e}")

            # Start the thread
            thread = threading.Thread(target=run_command)
            thread.start()
            messages.info(request, 'Nuclei scan against monitored hosts triggered in the background.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
        
    return redirect(reverse('findings:assets'))

@login_required
def gowitness_scan(request):
    context = {'projectid': request.session['current_project']['prj_id']}

    if request.method == 'GET':
        # Get the project ID from the session
        projectid = context['projectid']

        try:

            # Define a function to run the command in a separate thread
            def run_command():
                try:
                    # call_command("scan_gowitness", projectid=projectid)
                    pass
                except Exception as e:
                    print(f"Error running scan_gowitness: {e}")

            # Start the thread
            thread = threading.Thread(target=run_command)
            thread.start()
            messages.info(request, 'GoWitness scan against monitored hosts triggered in the background.')
        except Exception as e:
            messages.error(request, f'Error: {e}')
        
    return redirect(reverse('findings:assets'))