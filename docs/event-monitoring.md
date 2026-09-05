# Event monitoring, WEF, and Sysmon

BTPS includes several layers of event-driven visibility: local event alerts, Sysmon telemetry, and a Windows Event Forwarding (WEF) workflow that can centralize events for review.

## Start with logging coverage

Detection scripts can only alert on events that exist. Before tuning a task trigger or SQL query, confirm that the required audit policy, Windows Event Log channel, event ID, and retention settings are present on the systems you expect to monitor.

For a production rollout, document:

- Which event channels are collected.
- Which endpoints and servers are in scope.
- Retention capacity on endpoints and collectors.
- Collector authentication and transport security.
- Alert ownership and escalation procedures.
- Expected false positives and exclusions.

## Windows Event Forwarding application

The `WEF Application/` directory contains:

- `DomainComputers.xml` and `DomainControllers.xml` subscription material.
- `WEFStartupScript.ps1` for collector-related setup.
- `Import-EventsHourly.ps1` for event ingestion.
- `SQL-Query-Suspicous-Events.ps1` for reviewing selected suspicious activity.
- Scheduled-task XML definitions.
- A SQL query file used to create the expected database table.

The repository README for this component also describes WinRM/HTTPS, certificate requirements, event collector setup, and troubleshooting. Treat those values as templates: certificate subjects, thumbprints, identities, SQL settings, and host names must match your environment.

## Sysmon

The `Sysmon/` directory provides a Sysmon configuration and deployment helper. Sysmon can add process, network, file, registry, and other telemetry that is useful for investigation and detection, but verbose configurations can generate substantial event volume.

Recommended deployment sequence:

1. Review `sysmon.xml` and understand the included/excluded event categories.
2. Test event volume on a representative workstation and server.
3. Confirm the Sysmon executable source and hash.
4. Install using the project helper or your existing software-management system.
5. Forward only the telemetry you can store, review, and act on.
6. Tune noisy rules based on measured behavior, not guesswork.

## Alert examples

The repository already includes screenshots showing examples of generated detections and operational views. See {doc}`screenshots` for a visual tour.
