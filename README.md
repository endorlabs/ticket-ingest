# ticket-ingest

Python3 module and demo app to assist extraction of Endor Labs findings for ease of import into ticketing systems

# Install

**Requires python >= 3.11**

Clone, create a venv and activate it, then:

```zsh
pip3 install atlassian-python-api
```

# Command-line usage (alpha):

```
python3 -m endor_ticket_ingestion [secrets_file]
```

Module usage

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

# TODO

- [ ] Package as module
- [ ] Better docs
- [ ] Command-line options