# ticket-ingest

Python3 module and demo app to assist extraction of Endor Labs findings for ease of import into ticketing systems

# Install

**Requires python >= 3.11** --> check with `python3 --version`

Create a venv (e.g. `python3 -m venv .venv`) and activate it (e.g. `source .venv/bin/activate`), then:

```zsh
pip3 install 'git+https://github.com/endorlabs/ticket-ingest.git'
```

# Command-line usage (alpha):

```
usage: endor-ticket-ingestion [-h] [--filter FILTER] [--dry-run] [--group-by-dep] secrets_file

Ingests findings from Endor Labs into Jira issues

positional arguments:
  secrets_file     Path to a TOML secret file

options:
  -h, --help       show this help message and exit
  --filter FILTER  Specify a filter
  --dry-run        Don't actually create issues
  --group-by-dep   Use ingestion path that generates one issue per dependency version
```

Default secrets file is `ingestion.secret` in the current directory. Copy [ingestion.secret.example](ingestion.secret.example) and edit with your Endor Labs API and Jira Cloud URL/username/api-token ([manage your Atlassian Tokens here](https://id.atlassian.com/manage/api-tokens)) and additional ingestion configuration.

> **NOTE**: since these are credentials, please take care to make the file read only!

## `--group-by-dep`

This option changes the ingestion path to do the following:

* Create one Jira issue of type `issue_type` with a summary like "**[Endor Labs] Dependency *package_version* has *x* risks affecting *y* packages**"
  * The description of the issue will have a section for each 1st-party package affected by vulns in that package version
  * This single issue represents *all* the vulnerabilities in a given dependency, in *all* the 1st-party packages affected
* Create a sub-task to update the vulnerable dependency for each 1st-party package (i.e. each section in the main issue will have a subtask as well)
  * The type of the sub-task is defined by `subtask_type` in your Jira configuration section

This ingestion path has some downsides to be aware of:

* It only opens issues for _vulnerability_ finding types; you'll need to make sure your filter is set accordingly
* It has a higher chance of issue duplication, as it's more difficult to determine whether an issue is a duplicate when there are small changes to sub-issues or other contents
* It is _very_ noisy if your filter does not exclude "CI run" findings. We make an attempt to do this automatically, but strongly recommend testing throughly with `--dry-run` before opening tickets
* It does not attach reachable call-graph data to issues, since there's not a 1:1 issue:finding relationship; this may be improved in the future

**Note** to distinguish these tickets from other ingestion paths, the tickets created lead with `[Endor Labs]` rather than `[endor: <uuid>]`


# Module usage

```python
from endor_ticket_ingestion import ingest_findings
ingest_findings(secrets, 
        f"""
        {EndorLabsClient.FindingsFilter.inDirectDependency}
        and {EndorLabsClient.FindingsFilter.inProductionCode}
        and ({EndorLabsClient.FindingsFilter.sevIsCritical} or {EndorLabsClient.FindingsFilter.sevIsHigh})
        """,
        dry_run=False)
```

`secrets` is a dict intended to be read from `ingestion.secret`, a TOML file. See [`ingestion.secret.example`](ingestion.secret.example) for format, from which you can infer the dict structure

the second argument is a filter string, which can be built as pure text or using the `FindingsFilter` enum inside `EndorLabsClient`

# Usage notes

in `__main__.py` you will see that an issue filter has been defined with the following lines:

```python
DEFAULT_FILTER =f"""
{EndorLabsClient.FindingsFilter.inDirectDependency}
and {EndorLabsClient.FindingsFilter.inProductionCode}
and ({EndorLabsClient.FindingsFilter.sevIsCritical} or {EndorLabsClient.FindingsFilter.sevIsHigh})
"""
```

This filter can be modified to suit your needs; as written, it will pull all findings that meet all the following criteria:

- The finding is in a package that is a **Direct Dependency** of one of your org's package versions
- The finding is in production code (defined as "not test/build-only code")
- The finding's severity is Critical or High

**NOTE:** you cannot use these filter references through the `--filter` command line option; you must expand them yourself

----

The Jira ticket will have the UUID of the finding (in the form `[endor: UUID]`) -- this is to avoid creation of duplicate issues. The remainder of the issue summary will be the description of the remediation action. If the issue is not fixable, the summary is currently "No patch upgrades available to fix the issue. Check the security advisory for alternative controls or actions."

As long as the summary retains the `[endor: UUID]` component, you can change the rest of the summary text without risking a duplicate being opened.

# TODO

- [X] Package as module
- [X] Better docs
- [ ] Command-line options for more control (e.g. specify filters)
- [ ] Change summary for unfixable issues to be more useful
- [ ] get configuration from ENV variables to make it more suitable for CI actions
