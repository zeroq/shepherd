
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

# Create your views here.

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
def assets(request):
    context = {'projectid': request.session['current_project']['prj_id']}
    # check for POST request
    if request.method == 'POST':
        # determine action
        if "btnignore" in request.POST:
            action = "ignore"
        elif "btnmove" in request.POST:
            action = "move"
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
                    s_obj.is_monitored = False
                    s_obj.save()
                    # delete active entry
                    a_obj.delete()
                except Exception as error:
                    messages.error(request, 'Unknown: %s' % error)
                    continue # take next item
                messages.info(request, 'Moved Asset back to suggestions: %s' % s_obj.value)
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
                    s_obj.is_monitored = False
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
    s_obj.is_monitored = False
    s_obj.save()
    # delete active entry
    a_obj.delete()
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
    s_obj.is_monitored = False
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
def unignore_all_assets(request):
    """move all ignored assets back to active monitoring
    """
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('findings:ignored_assets'))
    # run over ignored assets
    prj_obj.activedomain_set.filter(monitor=False).update(monitor=True)
    messages.info(request, 'Updated successfully')
    return redirect(reverse('findings:ignored_assets'))

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
        # elif 'btnscan' in request.POST:
        #     prj_obj = Project.objects.get(id=context['projectid'])
        #     # get all active domains
        #     active_domains = prj_obj.activedomain_set.all().filter(monitor=True)
        #     # run nmap scan
        #     for ad in active_domains:
        #         # run nmap scan
        #         print('Running Nmap scan for: %s' % ad.value)
        #         nmap_results = nmap_scan(ad.value)
        #         for result in nmap_results:
        #             content = {
        #                 'domain': ad,
        #                 'port': result['port'],
        #             }
        #             port_obj, _ = Port.objects.get_or_create(**content)
        #             port_obj.domain_name = ad.value
        #             port_obj.scan_date = make_aware(datetime.now())
        #             port_obj.banner = result['banner']
        #             port_obj.status = result['status']
        #             port_obj.product = result['product']
        #             port_obj.cpe = result['cpe']
        #             port_obj.save()
        #     messages.info(request, 'Nmap scan completed')
        else:
            messages.error(request, 'Unknown action received!')
        print(request.POST)
    return render(request, 'findings/list_nmap_results.html', context)