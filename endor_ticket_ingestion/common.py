"""Common patterns for different ingestion paths
"""
import re
import sys
from sys import stdout, stderr
import json as jsonlib

from requests.exceptions import HTTPError
from atlassian import Jira

from endor_ticket_ingestion.endorlabs_client import EndorLabsClient

try:
    from rich import print as rich_print
except ModuleNotFoundError as e:
    pass


EndorJiraPriorityMap = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    #"??": "Lowest"
}

EndorPriorityRank = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def create_endor_client(secrets, findings_filter):
    endor = EndorLabsClient(
        secrets['endor']['namespace'],
        auth={
            'key': secrets['endor']['api_key'],
            'secret': secrets['endor']['api_secret']
        }
    )
    endor.filter = findings_filter
    return endor


def create_jira_client(secrets):
    jira_ticket_config = {
        'project': secrets['jira']['project'],
        'type': secrets['jira']['issue_type']
    }
    jira = Jira(
        url=secrets['jira']['url'],
        username=secrets['jira']['username'],
        password=secrets['jira']['token']
    )
    return jira, jira_ticket_config


def status(message, *args, file=sys.stderr, **kwargs):
    leader = '‣ '
    trailer = ''
    if 'rich_print' in globals():
        if isinstance(message, str):
            message = f'[blue]{message}[/blue]'
        return rich_print(f'[blue]{leader}[/blue]', message , *args, file=file, **kwargs)
    else:
        print(leader + str(message), *args, file=file, **kwargs)


def json_dump(obj: dict, *args, indent: int=4, **kwargs) -> str:
    return jsonlib.dumps(obj, *args, indent=indent, **kwargs)


def dict_dotpath(obj: dict, path: str, sep: str='.') -> object:
    fpath = path.split(sep)
    ref = obj
    while len(fpath):
        key = fpath.pop(0)
        if key.startswith('['):
            key = int(key.strip('[]'))
            ref = ref[key]
        else:
            ref = ref[key]

    return ref


def target_package_version(spec: dict) -> str:
    name = spec['target_dependency_name']
    ver_re = re.compile(r'@(.*?)$')
    vmatch = ver_re.match(name)
    if vmatch:
        status("Version identified: " + vmatch.group(1))
    else:
        name += '@' + str(spec['target_dependency_version'])

    return name