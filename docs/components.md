# Component catalog

This page maps the major repository directories to their intended defensive use. File names below match the repository so you can quickly locate the implementation.

## Account and password alerts

Directory: `Account and Password Alerts/`

| Tool | Purpose |
|---|---|
| `AccountsExpiringCheck.ps1` | Check for accounts approaching expiration. |
| `AttemptedPasswordChange.ps1` | Alert on attempted password-change activity. |
| `AttemptedPasswordReset.ps1` | Alert on password-reset activity. |
| `Failed.Username.and.Password.ps1` | Monitor failed username/password events. |
| `MonitorAdminEscalation.ps1` | Watch for administrative privilege escalation activity. |
| `PasswordExpiryAlert.ps1` | Notify about approaching password expiration. |
| `User.Account.Created.ps1` | Alert when a user account is created. |
| `User.Account.Locked.ps1` | Alert when an account is locked. |
| `User.Account.Unlocked.ps1` | Alert when an account is unlocked. |

Several scripts have matching `.xml` files that can be used as scheduled-task or event-trigger templates.

## Device discovery

Directory: `Device Discovery/`

`Find-NewDevices.ps1` is intended to identify newly observed devices, while `Get-MacVendor.ps1` can enrich MAC addresses using the included `MAC.Vendor.List.csv` dataset. See the directory's `README.md` for setup details and environment assumptions.

## Event alerts

Directory: `Event Alerts/`

The repository includes targeted alerting scripts for:

- DNS zone transfer activity.
- Newly installed services.
- Newly observed computers.
- Insecure LDAP bind review.
- Microsoft 365 forwarding-rule review.
- Unusual user sign-ins.

These scripts are most useful when the underlying event/audit sources are already configured correctly.

## Hardening cmdlets

Directory: `Hardening Cmdlets/`

This collection includes scripts for defensive configuration and administrative hygiene, including disabling NetBIOS/LMHOSTS and weak SSL, enabling DNS-over-HTTPS and HSTS, enforcing SMB signing and Network Level Authentication, removing PowerShell v2, repairing unquoted service paths, tightening file permissions, resetting Kerberos keys, reviewing exposed passwords, updating drivers, and Microsoft 365-related mail/security tasks.

:::{caution}
Hardening scripts can change system behavior. Validate compatibility with legacy applications, domain policy, management tooling, and recovery procedures before rollout.
:::

## Local port-scan monitor

Directory: `Local Port Scan Monitor/`

`ListenPortMonitor.ps1` and `Watch-PortScan.ps1`, together with the task XML files, provide local monitoring aimed at detecting suspicious port-scan behavior.

## Sysmon

Directory: `Sysmon/`

The Sysmon area contains an installer, Sysmon configuration, hash validation, malicious-IP checking, task XML files, and supporting binaries. Review the included `Sysmon/README.md` and confirm executable provenance and hashes before deployment.

## Windows Update cmdlets

Directory: `Windows Update Cmdlets/`

`Update-Windows.ps1` and `Remove-WindowsUpdate.ps1` support Windows update administration. Test removal operations carefully because update rollback can affect security posture and application stability.

## WEF application

Directory: `WEF Application/`

The Windows Event Forwarding material provides collector/subscription templates, scheduled task definitions, PowerShell import/query scripts, and a SQL schema/query workflow for centralized event review. See {doc}`event-monitoring` for an overview.
