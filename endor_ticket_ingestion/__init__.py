import io
import json

from .endorlabs_client import EndorLabsClient

from atlassian import Jira
from requests.exceptions import HTTPError


def ingest_findings(secrets, findings_filter, dry_run=False):
    # configure Client and Filter criteria
    endor = EndorLabsClient(secrets['endor']['namespace'], auth={'key': secrets['endor']['api_key'], 'secret': secrets['endor']['api_secret']})
    endor.filter = findings_filter


    JIRA_TICKET_CONFIG = {
        'project': secrets['jira']['project'],
        'type': secrets['jira']['issue_type']
    }

    jira = Jira(
        url=secrets['jira']['url'],
        username=secrets['jira']['username'],
        password=secrets['jira']['token']
    )

    for entry in endor.findings():
        finding=entry["finding"]

        jira_ticket = {
            'project': {'key': JIRA_TICKET_CONFIG['project']},
            'summary': f'[endor: {finding["uuid"]}] {finding["spec"]["remediation"]}',
            'description': finding["spec"]["summary"],
            'issuetype': {'name': JIRA_TICKET_CONFIG['type']},
        }

        # find out if theres already a ticket for this finding
        jira_results = jira.jql(f'project=SCA and summary ~ "endor: {finding["uuid"]}"')
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

