# itsm-automation

ServiceNow and ITIL automation for backup-related incident and change workflows.

The scripts turn backup platform events into ServiceNow incidents, generate ITIL-shaped change records for scheduled maintenance, and check runbooks for the sections ITSM process requires. They expect backup job events, maintenance windows, or runbook files as input, and produce ServiceNow records or lint output.

## Scripts

| Script | Purpose |
|---|---|
| `servicenow-incident-bridge` | Opens and resolves ServiceNow incidents from backup failure events. |
| `itil-change-record-generator` | Produces ITIL-shaped change records for scheduled maintenance. |
| `runbook-linter` | Lints runbooks for missing rollback, validation, and escalation sections. |

## Requirements

- Python 3.9+
- ServiceNow instance with REST API access and a service account with incident/change table permissions
- Network access from the host running these scripts to the ServiceNow instance

## Usage

```
python servicenow-incident-bridge.py --event backup-failure.json
python itil-change-record-generator.py --window maintenance-window.yaml
python runbook-linter.py --path ./runbooks/
```

Each script accepts `--help` for full argument details.

These scripts are generalised from production data-protection work and contain no customer data or site-specific configuration.
