import sys
import tomllib
from . import ingest_findings, HTTPError, EndorLabsClient

DRY_RUN = True  # set true if you don't want to create issues, but just see summaries of issues that would be created
SECRETS_FILE = 'ingestion.secret' if len(sys.argv) < 2 else sys.argv[1]

# load secrets from file

with open(SECRETS_FILE, 'rb') as secrets_file:
    secrets = tomllib.load(secrets_file)

try:
    ingest_findings(
        secrets, 
        f"""
        {EndorLabsClient.FindingsFilter.inDirectDependency}
        and {EndorLabsClient.FindingsFilter.inProductionCode}
        and ({EndorLabsClient.FindingsFilter.sevIsCritical} or {EndorLabsClient.FindingsFilter.sevIsHigh})
        """,
        dry_run=DRY_RUN)
except HTTPError as e:
    print(f'HTTP error {e.response.status_code}:\n{e.response.text}')
    exit(1)