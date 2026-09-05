# BTPS Security Package

```{raw} html
<div class="hero">
  <div class="hero-copy">
    <p class="eyebrow">Blue Team PowerShell</p>
    <h1>Practical Windows security tooling for smaller IT and security teams.</h1>
    <p class="hero-lede">BTPS is a collection of PowerShell scripts, scheduled-task templates, event-monitoring helpers, hardening commands, and incident-response utilities designed to improve visibility and defensive coverage in Windows-centric environments.</p>
    <div class="hero-actions">
      <a class="btn primary" href="getting-started.html">Get started</a>
      <a class="btn" href="components.html">Browse components</a>
      <a class="btn" href="https://github.com/OsbornePro/BTPS-SecPack">View on GitHub</a>
    </div>
  </div>
  <div class="hero-mark"><img src="_static/logo.png" alt="BTPS shield logo"></div>
</div>
```

:::{important}
BTPS is a defensive administration toolkit, not a substitute for a complete security program. Review every script before deployment, test changes in a non-production environment, and adapt paths, credentials, mail settings, scheduled tasks, and event subscriptions to your organization.
:::

## What is included?

::::{grid} 1 2 2 3
:gutter: 3

:::{grid-item-card} Account & password alerts
:link: components
:link-type: doc
Monitor lockouts, unlocks, expiring accounts, password activity, and account creation.
:::

:::{grid-item-card} Windows hardening
:link: components
:link-type: doc
PowerShell helpers for SMB signing, NLA, weak SSL removal, DoH, HSTS, file permissions, Kerberos keys, and more.
:::

:::{grid-item-card} Event monitoring
:link: event-monitoring
:link-type: doc
Tools for suspicious sign-ins, service creation, DNS zone transfers, LDAP binds, Sysmon, WEF, and local port-scan monitoring.
:::

:::{grid-item-card} Device discovery
:link: components
:link-type: doc
Find newly observed devices and enrich MAC addresses with vendor information.
:::

:::{grid-item-card} Incident response
:link: incident-response
:link-type: doc
Utilities for locating user sessions and helping remediate compromised Microsoft 365 accounts.
:::

:::{grid-item-card} Scheduled deployment
:link: getting-started
:link-type: doc
Installer and task-import helpers provide a starting point for repeatable deployment.
:::
::::

## Recommended reading order

Start with {doc}`getting-started`, review the {doc}`security-and-safety` notes, and then choose the relevant area from {doc}`components`. For event collection and alerting, continue to {doc}`event-monitoring`. If you are responding to a suspected compromise, see {doc}`incident-response`.

## Project links

- [GitHub repository](https://github.com/OsbornePro/BTPS-SecPack)
- [OsbornePro](https://osbornepro.com/)
- [Contributing guide](https://github.com/OsbornePro/BTPS-SecPack/blob/master/CONTRIBUTING.md)
- [Security policy](https://github.com/OsbornePro/BTPS-SecPack/blob/master/SECURITY.md)
- [License](https://github.com/OsbornePro/BTPS-SecPack/blob/master/LICENSE)

```{toctree}
:hidden:
:maxdepth: 2

getting-started
components
event-monitoring
incident-response
screenshots
security-and-safety
contributing
```
