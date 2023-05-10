"""Ingest Findings grouped by package version of dependency

Each ticket has:

- A Summary indicating the affected dependency package version
- A Description/body listing each finding related to that package version, including
    - A short description of the issue
    - A link to the finding in the Endor Labs UI
    - A link to the CVE / related disclosure key
    - CVSS, if available
    - Finding Severity
    - EPSS score, if available
- A Severity set to the highest Finding Severity associated with that dependency
"""

## Approach
"""
1. Get findings with filters applied
2. Parse each finding:
    a. get the affected dep version, add it as a key to the findings dict if it doesn't exist
    b. append the finding data to the the packver findings key value
    c. set the max_severity if finding sev is higher than current setting
"""

from endor_ticket_ingestion import common
from endor_ticket_ingestion.endorlabs_client import EndorLabsClient

def ingest_findings_by_dep_ver(secrets, findings_filter, dry_run=False):
    if 'CONTEXT_TYPE_CI_RUN' not in findings_filter:
        common.status(f"NOTICE: adding {EndorLabsClient.FindingsFilter.notFromCIRun} to findings filter to avoid duplicates")
        findings_filter = f"{EndorLabsClient.FindingsFilter.notFromCIRun} and ({findings_filter})"

    endor = common.create_endor_client(secrets, findings_filter)
    jira, JIRA_TICKET_CONFIG = common.create_jira_client(secrets)
    configured_priority_map = secrets['jira'].get('priority', None)
    prioritymap = common.EndorJiraPriorityMap 
    if configured_priority_map is not None:
        prioritymap |= configured_priority_map  # merge the configuration

    print(prioritymap)

    dependencies = {}
    for entry in endor.findings():
        # print(common.json_dump(entry))
        # exit(1)
        # dep_name = common.dict_dotpath(entry, 'finding.spec.target_dependency_name')
        dep_name = common.target_package_version(common.dict_dotpath(entry, 'finding.spec'))
        if dep_name not in dependencies:
            dependencies[dep_name] = {
                'uuid': common.dict_dotpath(entry, 'finding.spec.target_uuid'),
                'name': dep_name,
                'findings': [],
                'affected': {}
            }
        
        dependencies[dep_name]['findings'].append(entry)
        finding_index = len(dependencies[dep_name]['findings'])-1
        affected = common.dict_dotpath(entry, 'myPackage.meta.name')
        if affected not in dependencies[dep_name]['affected']:
            dependencies[dep_name]['affected'][affected] = []
        dependencies[dep_name]['affected'][affected].append(finding_index)
        # print(common.json_dump(dependencies)) ; exit(1)
    
    common.status(f"{len(dependencies.keys())} dependencies with findings")
    for dep_name, data in dependencies.items():
        issue = {
            'project': {'key': JIRA_TICKET_CONFIG['project']},
            'summary': f'[Endor Labs] Dependency {dep_name} has {len(data["findings"])} risks affecting {len(data["affected"])} packages',
            'description': '',
            'issuetype': {'name': JIRA_TICKET_CONFIG['type']},
        }
        common.status(f"{dep_name} ({data['uuid']}): {len(data['findings'])} findings")

        issue_priority = len(common.EndorPriorityRank)-1  # Higher numbers == lower priority
        subtasks = []
       
        for pkg_name, indices in data['affected'].items():
            description = issue['description']
            description += f"h2. In package *{pkg_name}*:\n\n"
            subdesc = "||Summary||Advisory||Score||Severity||\n"
            subpriority = len(common.EndorPriorityRank)-1
            subissue = {
                'project': {'key': JIRA_TICKET_CONFIG['project']},
                'summary': f'[Endor Labs] Update {dep_name} in {pkg_name}',
                'description': '',
                'issuetype': {'name': JIRA_TICKET_CONFIG['subtype']},
            }

            for i in indices:
                try:
                    finding = data['findings'][i]['finding']
                    meta = finding['spec']['finding_metadata']
                    dep_ver_name = common.target_package_version(finding['spec'])
                    summary = f"{dep_ver_name}: " + common.dict_dotpath(meta, 'vulnerability.meta.description')
                    advisory = common.dict_dotpath(meta, 'vulnerability.meta.name')
                    if advisory.startswith('GHSA-'):
                        advisory = f"[{advisory}|https://github.com/advisories/{advisory}]"
                    cvss = common.dict_dotpath(meta, 'vulnerability.spec.cvss_v3_severity.score')
                    epss = float(common.dict_dotpath(meta, 'vulnerability.spec.epss_score.probability_score')) * 100
                    level = common.dict_dotpath(meta, 'vulnerability.spec.cvss_v3_severity.level').removeprefix('LEVEL_')
                except Exception as e:
                    print(common.json_dump(data['findings'][i]))
                    raise e

                finding_priority = common.EndorPriorityRank.index(level)
                if finding_priority < issue_priority:
                    issue_priority = finding_priority
                if finding_priority < subpriority:
                    subpriority = finding_priority
                subdesc += f"|{summary}|{advisory}|CVSS: {cvss}\nEPSS: {epss:2.1f}%|{level}|\n"
                description += subdesc

            #--- back to affected package level --
            subissue['description'] = subdesc
            subissue['priority'] = {'name': prioritymap[common.EndorPriorityRank[subpriority]]}

            issue['description'] = description + "\n"
            subtasks.append(subissue)
            # print(issue['description'])
            # print(common.json_dump(issue))
        
        #=== back to dep level ===
        # find out if theres already a ticket for this dependency
        # TODO can we link to other tickets for that dependency?
        # TODO find out why duplicate detection fails on com.h2database:h2@1.4.197
        common.status(f"Priority level for this issue is {issue_priority}: {common.EndorPriorityRank[issue_priority]} => {prioritymap[common.EndorPriorityRank[issue_priority]]}")
        issue['priority'] = {'name': prioritymap[common.EndorPriorityRank[issue_priority]]}
        try:
            jira_results = jira.jql(f'project="{secrets["jira"]["project"]}" and summary ~ "{issue["summary"]}"')
            if jira_results['issues']:
                for issue in jira_results['issues']:
                    common.status(f'Found matching issue {issue["key"]} {issue["fields"]["summary"]}')  
            elif dry_run:
                common.status('Would create a ticket: '+issue["summary"])
                for st in subtasks:
                    common.status(f'  -> Would create sub-task: {st["summary"]}, priority {st["priority"]["name"]}')
            else:
                # there wasn't a duplicate, let's create a new issue!
                jira_issue = jira.create_issue(issue)
                # attachment = io.StringIO(json.dumps(finding["spec"]["reachable_paths"]))
                # attachment.filename = f'reachable_paths-{finding["uuid"]}.json'
                common.status(f'Created {jira_issue["key"]}')
                # jira.add_attachment_object(jira_issue["key"], attachment)
                for st in subtasks:
                    st['parent'] = {'key': jira_issue["key"]}
                    jira.create_issue(st)
        except common.HTTPError as err:
            msg = f'HTTP Error communicating with Jira: {err.response.status_code}\n--> {err.response.url}\n--> {err.response.text}'
            if err.response.status_code == 404:
                raise RuntimeError(f'{msg}\nPlease check your configuration and make sure your Jira URL is set correctly')

            if err.response.status_code >= 400 and err.response.status_code <= 403:
                raise RuntimeError(f'{msg}\nPlease check that your userid and token are correct and your account can access the above URL')
            
            raise RuntimeError(f'{msg}')

