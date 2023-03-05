# ticket-ingest

Python3 module and demo app to assist extraction of Endor Labs findings for ease of import into ticketing systems

# Install

**Requires python >= 3.11** --> check with `python3 --version`

Create a venv (e.g. `pythnon3 -v venv .venv`) and activate it (e.g. `source .venv/bin/activate`), then:

```zsh
pip3 install 'git+https://github.com/endorlabs/ticket-ingest.git'
```

# Command-line usage (alpha):

```
endor-ticket-ingestion [secrets_file]
```

Default secrets file is `ingestion.secret` in the current directory. Copy [ingestion.secret.example](ingestion.secret.example) and edit with your Endor Labs API and Jira Cloud URL/username/api-token ([manage your Atlassian Tokens here](https://id.atlassian.com/manage/api-tokens)).

> **NOTE**: since these are credentials, please take care to make the file read only!


# Module usage

```python
from endor_ticket_ingestion import ingest_findings
ingest_findings(
        secrets, 
        f"""
        {EndorLabsClient.FindingsFilter.inDirectDependency}
        and {EndorLabsClient.FindingsFilter.inProductionCode}
        and ({EndorLabsClient.FindingsFilter.sevIsCritical} or {EndorLabsClient.FindingsFilter.sevIsHigh})
        """)
```

`secrets` is a dict intended to be read from `ingestion.secret`, a TOML file. See [`ingestion.secret.example`](ingestion.secret.example) for format, from which you can infer the dict structure

# Usage notes

in `__main__.py` you will see that an issue filter has been defined with the following lines:

```python
            f"""
            {EndorLabsClient.FindingsFilter.inDirectDependency}
            and {EndorLabsClient.FindingsFilter.inProductionCode}
            and ({EndorLabsClient.FindingsFilter.sevIsCritical} or {EndorLabsClient.FindingsFilter.sevIsHigh})
            """,
```

This filter can be modified to suit your needs; as written, it will pull all findings that meet all the following criteria:

- The finding is in a package that is a **Direct Dependency** of one of your org's package versions
- The finding is in production code (defined as "not test/build-only code")
- The finding's severity is Critical or High

----

The Jira ticket will have the UUID of the finding (in the form `[endor: UUID]`) -- this is to avoid creation of duplicate issues. The remainder of the issue summary will be the description of the remediation action. If the issue is not fixable, the summary is currently "No patch upgrades available to fix the issue. Check the security advisory for alternative controls or actions."

As long as the summary retains the `[endor: UUID]` component, you can change the rest of the summary text without risking a duplicate being opened.

# TODO

- [X] Package as module
- [X] Better docs
- [ ] Command-line options for more control (e.g. specify filters)
- [ ] Change summary for unfixable issues to be more useful
- [ ] get configuration from ENV variables to make it more suitable for CI actions
