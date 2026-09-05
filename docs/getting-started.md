# Getting started

BTPS is designed as a collection of Windows-focused defensive scripts rather than a single monolithic application. You can use individual tools or deploy a larger subset, depending on the visibility and hardening needs of your environment.

## Prerequisites

Before deploying anything, use an administrative PowerShell session where required and make sure the target systems meet the assumptions of the specific script. Many alerting features depend on suitable Windows audit policy and event logging being enabled. The project recommends reviewing a Windows event-logging baseline before relying on event-triggered detections.

You should also plan for these operational requirements where applicable:

- A supported Windows or Windows Server environment.
- PowerShell with the permissions required by the selected script.
- Administrative access for hardening or system-level changes.
- Correctly configured Windows Event Logs for event-based alerts.
- SMTP or another notification path where a script sends email.
- A safe method for storing secrets instead of embedding plaintext credentials.
- Code-signing and restricted file permissions for production scripts where your policy requires them.

## Clone the repository

```powershell
Git clone https://github.com/OsbornePro/BTPS-SecPack.git
Set-Location .\BTPS-SecPack
```

If Git is not available, download the repository from GitHub and extract it to a controlled administrative location.

## Choose an installation approach

### Use a single component

For most environments, the safest path is to start with one capability. Read the script and any README in its directory, update environment-specific settings, test it, and only then create the associated scheduled task or event trigger.

### Use the project installer

The repository also includes `Installer.ps1` as a deployment helper. Read it before execution because it can make system-level changes and may deploy multiple components.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Installer.ps1
```

:::{warning}
Do not treat the command above as a blanket recommendation to bypass your organization's PowerShell policy. `-Scope Process` limits the change to the current process, but you should follow your own execution-policy and code-signing standards.
:::

## Import a scheduled-task template

The root `Import-ScheduledTask.ps1` helper and multiple XML task definitions can be used to install recurring or event-triggered jobs. Before importing any template, verify the executable/script path, run-as account, trigger, permissions, and arguments.

A useful production pattern is:

1. Copy the selected script to a directory writable only by administrators.
2. Update all environment-specific variables.
3. Sign the script if your environment requires signed PowerShell.
4. Import or create the scheduled task using a least-privilege service identity where practical.
5. Run a controlled test and confirm logs/alerts are generated as expected.
6. Document rollback steps before broad deployment.

## Where to go next

Use {doc}`components` to find the script family that matches your goal. For centralized Windows Event Forwarding and Sysmon material, see {doc}`event-monitoring`. For response actions, see {doc}`incident-response`.
