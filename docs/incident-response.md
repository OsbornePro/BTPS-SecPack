# Incident response helpers

The `Incident Response/` directory contains targeted PowerShell utilities intended to help administrators answer common response questions and perform account-focused remediation.

## Find where a user is logged in

`Find-WhereUserIsLoggedIn.ps1` can help locate active user sessions in a Windows environment. This is useful during account compromise triage, but results should be correlated with authentication logs, endpoint telemetry, VPN records, and identity-provider sign-in data where available.

## Remediate a compromised Microsoft 365 account

`RemediateCompromisedOfficeAccount.ps1` is intended to assist with Microsoft 365 account-compromise response. Before using it, inspect the current script and confirm that its actions align with your tenant, authentication model, licensing, incident-response procedure, and retention requirements.

A typical response process also includes preserving evidence, reviewing sign-in history, removing malicious inbox/forwarding rules, revoking active sessions or tokens where appropriate, resetting credentials, validating MFA, reviewing privileged role assignments, and monitoring for persistence.

:::{important}
Automated remediation can alter or destroy evidence. If an incident may require forensic investigation, legal review, insurance reporting, or law-enforcement involvement, coordinate evidence preservation before running destructive response actions.
:::

## After containment

After immediate containment, use the account/password alerting, event-alert, WEF, and Sysmon components to improve follow-up visibility. Record what was changed so the response can be audited and reversed if needed.
