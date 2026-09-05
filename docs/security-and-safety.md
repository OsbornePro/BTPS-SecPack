# Security and deployment safety

BTPS contains administrative and security-sensitive PowerShell. Treat the repository as source code to review and adapt, not as an opaque installer.

## Review before execution

Read each script you plan to run. Pay special attention to network destinations, downloaded content, module installation, registry changes, service changes, scheduled tasks, certificate handling, SMTP settings, Microsoft 365 actions, and any command that changes authentication or security policy.

## Protect credentials and secrets

Do not commit passwords, application secrets, API keys, SMTP credentials, private keys, or reusable access tokens into the repository. Prefer a supported secret store such as an enterprise vault or platform-specific secret-management solution, and scope the consuming identity to the minimum permissions needed.

## Verify binaries

The repository contains executable files in some component directories. Before deploying binaries from any repository, confirm their expected source, signature where available, version, and cryptographic hash. In higher-assurance environments, obtain vendor binaries directly through your approved software-distribution process.

## Use least privilege

Run scheduled tasks and services under the least-privileged identity that can perform the required operation. Restrict write access to deployed scripts so an unprivileged user cannot replace a script that later runs as an administrator or service account.

## Test hardening changes

Security controls can break legacy dependencies. Test protocol, registry, cipher, authentication, SMB, NLA, DNS, and service-path changes on representative systems before broad deployment. Have a documented rollback path.

## Logging and privacy

Centralized event monitoring can collect usernames, hostnames, IP addresses, process information, file paths, and other operational data. Apply your organization's access controls, retention rules, privacy requirements, and incident-handling procedures to that data.

## Reporting a vulnerability

Follow the repository's [security policy](https://github.com/OsbornePro/BTPS-SecPack/blob/master/SECURITY.md) for vulnerability reporting rather than disclosing a security issue publicly before the maintainer has had a chance to evaluate it.
