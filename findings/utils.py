#

import requests
import json
import html


def asset_finding_get_or_create(asset_id, vuln_obj, url, request_header):
    #rsp = requests.get(url+'/projects/3000003/assets/%s/findings' % (asset_id), headers=request_header, verify=True)
    #findings_list = rsp.json()
    #finding_exists = False
    #if len(findings_list)>0:
    #    for finding in findings_list:
    #        print(finding)
    #        if finding['finding_name'] == html.escape(vuln_obj.raw.get('vulnerabilityName')): # cannot just distinguish by name
    #            finding_exists = True
    #            break
    #if finding_exists is True:
    #    return False, "Entry Exists"


    severity = vuln_obj.raw.get('severity').capitalize()
    if severity == 'Info':
        severity = 'Informational'

    new_finding = {
        "host_id": asset_id,
        "custom_finding_type": "Web Application",
        "custom_finding_name": vuln_obj.raw.get('vulnerabilityName'),
        "custom_finding_description": vuln_obj.raw.get('description'),
        "custom_finding_severity": severity,
        "custom_finding_source": vuln_obj.source,
        "custom_finding_reference": vuln_obj.raw.get('reference'),
        "custom_finding_recommendation": vuln_obj.raw.get('solution'),
        "finding_url": vuln_obj.raw.get('vulnerableAt'),
        "finding_additional_information": vuln_obj.raw.get('vulnerabilityDetail'),
        "finding_code_snippet": vuln_obj.raw.get('curl'),
        "custom_finding_cvss": vuln_obj.raw.get('cvss-metrics'),
    }
    try:
        cve = vuln_obj.raw.get('cve-id')[0]
        new_finding['custom_finding_cve'] = cve
    except:
        pass
    rsp = requests.post(url+'/projects/3000003/findings', headers=request_header, json=new_finding, verify=False)
    print(json.dumps(rsp.json(), indent=4))
    return True, "Entry Created"

def asset_get_or_create(asset_name, url, request_header):
    entry_name = None
    entry_id = None
    request_parameter = {
        "asset_name": asset_name,
    }
    rsp = requests.get(url+'/projects/3000003/assets', headers=request_header, params=request_parameter, verify=False)
    result_list = rsp.json()
    if len(result_list)>0:
        entry = result_list[0]
        entry_name = entry['asset_name']
        entry_id = entry['asset_id']
        return entry_name, entry_id
    else:
        request_parameter = {
            "asset_name": asset_name,
            "asset_type": "Application",
            "asset_notes": "created with Shepherd automation",
            "asset_groups": ["test"],
            "asset_criticality": "High",
            "asset_public": True,
        }
        rsp = requests.post(url+'/projects/3000003/assets', headers=request_header, json=request_parameter, verify=False)
        response = rsp.json()
        if response['success'] is True:
            entry_name = asset_name
            entry_id = response['asset_id']
        else:
            print('ERROR')
            print(json.dumps(rsp.json(), indent=4))
            return None, None
    return entry_name, entry_id
