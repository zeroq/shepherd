from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.utils.timezone import make_aware
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.conf import settings

import uuid as imported_uuid

from project.models import Suggestion, ActiveDomain, Project
from suggestions.forms import AddSuggestionForm

import requests
import json
import dateparser
from datetime import datetime
from urllib.parse import urlencode, quote_plus

# Create your views here.

@login_required
def suggestions(request):
    """view all new and open suggestions
    """
    context = {'projectid': request.session['current_project']['prj_id'], 'suggestionform': AddSuggestionForm()}
    # check for POST request
    if request.method == 'POST':
        # determine action
        if "btnmonitor" in request.POST:
            action = "monitor"
        elif "btnignore" in request.POST:
            action = "ignore"
        elif "btndelete" in request.POST:
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
                        m_obj = ActiveDomain.objects.get(uuid=s_obj.uuid)
                    except ActiveDomain.DoesNotExist:
                        # copy to activedomain table
                        m_obj = ActiveDomain()
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
                    s_obj.is_monitored = True
                    s_obj.save()
                    messages.info(request, 'Added %s to the monitoring' % s_obj.value)
                else:
                    messages.error(request, 'Unsupported finding type: %s' % s_obj.finding_type)
                    continue
        # redirect to suggestion list
        return redirect(reverse('suggestions:suggestions'))
    else:
        prj = Project.objects.get(id=request.session['current_project']['prj_id'])
        context['domain_count'] = prj.suggestion_set.filter(finding_type='domain', finding_subtype='domain', ignore=False, is_monitored=False).count()
        context['subdomain_count'] = prj.suggestion_set.filter(finding_type='domain', finding_subtype='subdomain', ignore=False, is_monitored=False).count()
        context['ip_count'] = 0 # TODO: fix this
        context['activetab'] = 'domain'
    return render(request, 'suggestions/list_suggestions.html', context)

@login_required
def manual_add_suggestion(request):
    """manually add a suggestion
    """
    if request.method == 'POST':
        form = AddSuggestionForm(request.POST)
        if form.is_valid():
            record = form.save(commit=False)
            record.uuid = imported_uuid.uuid5(imported_uuid.NAMESPACE_DNS, "%s" % record.value)
            record.creation_time = timezone.now()
            record.save()
            messages.info(request, "Suggestion successfully added")
        else:
            messages.error(request, "Suggestion failed: %s", form.errors.as_json(escape_html=False))
    return redirect(reverse('suggestions:suggestions'))
    #context = {'projectid': request.session['current_project']['prj_id'], 'suggestionform': AddSuggestionForm()}
    #return render(request, 'suggestions/list_suggestions.html', context)


@login_required
def ignored_suggestions(request):
    """view all ignored suggestions
    """
    context = {'projectid': request.session['current_project']['prj_id']}
    # check for POST request
    if request.method == 'POST':
        # determine action "move" or "delete"
        if "btnmove" in request.POST:
            action = 'move'
        elif "btndelete" in request.POST:
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
    try:
        s_obj = Suggestion.objects.get(uuid=uuid)
    except Suggestion.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:suggestions'))
    if s_obj.finding_type in ['certificate', 'domain']:
        # check if entry already exists
        try:
            m_obj = ActiveDomain.objects.get(uuid=s_obj.uuid)
        except ActiveDomain.DoesNotExist:
            # copy to activedomain table
            m_obj = ActiveDomain()
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
        s_obj.is_monitored = True
        s_obj.save()
        messages.info(request, 'Added %s to the monitoring' % s_obj.value)
        return redirect(reverse('suggestions:suggestions'))
    # if nothing matches it is not supported
    messages.error(request, 'Unsupported finding type: %s' % s_obj.finding_type)
    return redirect(reverse('suggestions:suggestions'))

@login_required
def ignore_suggestion(request, uuid):
    """move suggestion to the ignore list
    """
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
    try:
        s_obj = Suggestion.objects.get(uuid=uuid)
    except Suggestion.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:ignored_suggestions'))
    s_obj.ignore = False
    s_obj.save()
    return redirect(reverse('suggestions:ignored_suggestions'))

@login_required
def recent_suggestions(request):
    """list recent suggestions
    """
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('projects:projects'))
    context['past_days'] = settings.RECENT_DAYS
    return render(request, 'suggestions/list_recent_suggestions.html', context)

@login_required
def delete_all_suggestions(request):
    """delete all suggestions in given project
    """
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
def ignore_star_suggestions(request):
    """ move all *. suggestions to ignore
    """
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('suggestions:suggestions'))
    # run over suggestions
    prj_obj.suggestion_set.filter(value__contains='*', ignore=False).update(ignore=True)
    messages.info(request, 'Suggestions Updated successfully')
    return redirect(reverse('suggestions:suggestions'))

@login_required
def update_suggestions(request):
    """update suggestions
    """
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
