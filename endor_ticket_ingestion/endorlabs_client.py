import os, sys
import enum

# imported from atlassian-python-api package
import requests

class EndorLabsClient(object):
    MAX_API_ERRORS = 3
    class FindingsFilter(enum.StrEnum):
        inDirectDependency = 'spec.finding_tags Contains "FINDING_TAGS_DIRECT"'
        inProductionCode = 'spec.finding_tags Contains "FINDING_TAGS_NORMAL"'
        inReachableDependcy = 'spec.finding_tags Contains "FINDING_TAGS_REACHABLE_DEPENDENCY"'
        inReachableFunction = 'spec.finding_tags Contains "FINDING_TAGS_REACHABLE_FUNCTION"'
        sevIsLow = 'spec.level=="FINDING_LEVEL_LOW'
        sevIsMedium = 'spec.level=="FINDING_LEVEL_MEDIUM'
        sevIsHigh = 'spec.level=="FINDING_LEVEL_HIGH"'
        sevIsCritical = 'spec.level=="FINDING_LEVEL_CRITICAL"'
        hasFixAvailable = 'spec.finding_tags Contains "FINDING_TAGS_FIX_AVAILABLE"'
        fixIsUpgrade = 'spec.remediation_action=="FINDING_REMEDIATION_UPGRADE"'
        fromCIRun = 'context.type=="CONTEXT_TYPE_CI_RUN"'
        notFromCIRun = 'context.type!="CONTEXT_TYPE_CI_RUN"'

    def __init__(self, namespace, auth=None, findings_filter=None, api_root='https://api.endorlabs.com'):
        """Connection to the EndorLabs API

        Args:
            namespace (str): Endor Labs tenant/namespace name
            auth (dict, optional): the API key and secret for EndorLabs in the form {'key': keyID, 'secret', keySecret}
            findings_filter (str, optional): default filter to use when querying findings. Defaults to None.
            api_root (str, optional): Root URL for EndorLabs API. Defaults to 'https://api.endorlabs.com'. Do not change unless you're sure
        """
        self.auth = auth
        self._api_root = api_root
        self.namespace = namespace
        self.filter = self.FindingsFilter.inDirectDependency if findings_filter is None else findings_filter
        self._token = None
        self._token_expires = None
        self._session = requests.Session()

    def refresh_auth(self, nocache=False):
        """Update Session headers with new bearer token
        """
        if not nocache and self._token is not None:
            # TODO only return if current time is close to self._token_expires
            return

        response = requests.post(f'{self._api_root}/v1/auth/api-key', json=self.auth)
        self._token = response.json()['token']
        self._token_expires = response.json()['expirationTime']
        self._session.headers.update({'Authorization': 'Bearer ' + self._token})

    def findings(self, findings_filter=None):
        self.refresh_auth()
        # default to instance filter if one isn't specified on call
        findings_filter = self.filter if findings_filter is None else findings_filter

        page_token = 0
        seen_uuid = {}
        packages_cache = {}
        duplicates = []
        pages_remain = True

        findings_list = []
        error_count = 0
        while pages_remain:
            response = self._session.get(
                f'{self._api_root}/v1/namespaces/{self.namespace}/findings', 
                params={'list_parameters.filter': findings_filter, 'list_parameters.page_token': int(page_token)})

            if response.status_code != 200:
                error_count += 1
        
                if response.status_code == 404:
                    req = response.request
                    print(f"404 on {req.method} {req.url}", file=sys.stderr)
                    print(f"Token expiration: {self._token_expires}", file=sys.stderr)
                
                print(response.text)
                if error_count >= self.MAX_API_ERRORS:
                    raise RuntimeError("Too many API errors for comfort")
                continue

            result = response.json()
            findings = result['list']['objects']

            for finding in findings:
                # avoid duplicates in results
                if finding['uuid'] in seen_uuid:
                    duplicates.append(finding['uuid'])
                    print(f"found duplicate uuid: {finding['uuid']}", file=sys.stderr)
                    continue

                seen_uuid[finding['uuid']] = True

                # Get package for meta.parent_uuid,
                customer_package_uuid = finding['meta']['parent_uuid']
                customer_package = None
                if customer_package_uuid in packages_cache:
                    # avoid querying Endor API twice for the same PackageVersion
                    customer_package = packages_cache[customer_package_uuid]
                else:
                    response = self._session.get(
                        f'{self._api_root}/v1/namespaces/{self.namespace}/package-versions',
                        params={ 'list_parameters.filter': f'uuid=={customer_package_uuid}' })

                    customer_package = response.json()['list']['objects'][0]
                    packages_cache[customer_package_uuid] = customer_package

                finding_dict = {
                    'myPackage': customer_package,
                    'finding': finding
                }
                findings_list.append(finding_dict)
                # end for findings

            next_page = result['list']['response']['next_page_token']
            if next_page is not None:
                page_token = next_page
                print(f"Next page starts at {next_page}; set page token to {page_token}", file=sys.stderr)
            else:
                pages_remain = False
            # end while pages_remain
        
        return findings_list

