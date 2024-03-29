import os
import sys
import tomllib
import argparse
from . import ingest_findings, HTTPError
from .endorlabs_client import EndorLabsClient
from .ingest_by_packagever import ingest_findings_by_dep_ver

# Change this filter to a default that works for you
DEFAULT_FILTER =f"""
{EndorLabsClient.FindingsFilter.notFromCIRun} and (
{EndorLabsClient.FindingsFilter.inDirectDependency}
and {EndorLabsClient.FindingsFilter.inProductionCode}
and ({EndorLabsClient.FindingsFilter.sevIsCritical} or {EndorLabsClient.FindingsFilter.sevIsHigh})
)
"""


def cli():
    try:
        argparser = argparse.ArgumentParser(description='Ingests findings from Endor Labs into Jira issues')
        argparser.add_argument('--filter', default=DEFAULT_FILTER, help='Specify a filter')
        argparser.add_argument('--dry-run', action='store_true', help='Don\'t actually create issues')
        argparser.add_argument('--group-by-dep', action='store_true', help='Use ingestion path that generates one issue per dependency version')
        argparser.add_argument('secrets_file', default='ingestion.secret', help='Path to a TOML secret file')
        args = argparser.parse_args()

        # load secrets from file
        with open(args.secrets_file, 'rb') as secrets_file:
            secrets = tomllib.load(secrets_file)

        try:
            if args.group_by_dep:
                ingest_findings_by_dep_ver(secrets, args.filter, dry_run=args.dry_run)
            else:
                ingest_findings(secrets, args.filter, dry_run=args.dry_run)
        except HTTPError as e:
            print(f'HTTP error {e.response.status_code}:\n{e.response.text}')
            return 1
        except RuntimeError as e:
            print(f'Error: {str(e)}')
    except KeyboardInterrupt as err:
        print("** Execution interrupted by Ctrl-C **", file=sys.stderr)
        return 127


if __name__ == '__main__':
    cli()
    
