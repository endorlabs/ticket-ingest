import io
import json

from . import common

from requests.exceptions import HTTPError


def ingest_findings(secrets, findings_filter, dry_run=False):
    # configure Client and Filter criteria
    endor = common.create_endor_client(secrets, findings_filter)
    jira, JIRA_TICKET_CONFIG = common.create_jira_client(secrets)

    for entry in endor.findings():
        finding=entry["finding"]

        jira_ticket = {
            'project': {'key': JIRA_TICKET_CONFIG['project']},
            'summary': f'[endor: {finding["uuid"]}] {finding["spec"]["remediation"]}',
            'description': finding["spec"]["summary"],
            'issuetype': {'name': JIRA_TICKET_CONFIG['type']},
        }

        # find out if theres already a ticket for this finding
        try:
            jira_results = jira.jql(f'project="{secrets["jira"]["project"]}" and summary ~ "endor: {finding["uuid"]}"')
            if jira_results['issues']:
                for issue in jira_results['issues']:
                    print(f'Found matching issue {issue["key"]} {issue["fields"]["summary"]}')  
            elif dry_run:
                print('Would create a ticket: '+jira_ticket["summary"])
            else:
                # there wasn't a duplicate, let's create a new issue!
                jira_issue = jira.create_issue(jira_ticket)
                attachment = io.StringIO(json.dumps(finding["spec"]["reachable_paths"]))
                attachment.filename = f'reachable_paths-{finding["uuid"]}.json'
                print(f'Created {jira_issue["key"]}', end='')
                jira.add_attachment_object(jira_issue["key"], attachment)
        except HTTPError as err:
            msg = f'HTTP Error communicating with Jira: {err.response.status_code}\n--> {err.response.url}\n--> {err.response.text}'
            if err.response.status_code == 404:
                raise RuntimeError(f'{msg}\nPlease check your configuration and make sure your Jira URL is set correctly')

            if err.response.status_code >= 400 and err.response.status_code <= 403:
                raise RuntimeError(f'{msg}\nPlease check that your userid and token are correct and your account can access the above URL')
            
            raise RuntimeError(f'{msg}')

