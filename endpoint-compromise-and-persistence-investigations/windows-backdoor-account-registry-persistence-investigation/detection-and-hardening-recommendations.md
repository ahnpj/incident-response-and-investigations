# Detection and Hardening Recommendations — Windows Host Compromise Investigation (Backdoor Account Creation and Registry-Based Persistence)

## Purpose and Scope

This report documents detailed preventive controls and detection engineering recommendations based directly on behaviors confirmed during the investigation of a Windows host compromise involving unauthorized account creation, registry-based persistence, and abuse of built-in administrative tools.

Recommendations in this document are derived from specific findings documented in:

- `windows-backdoor-account-registry-persistence-investigation.md` (exact analyst pivots, log filters, and validation steps)
- `case-report.md` (reconstructed attacker activity timeline and business impact framing)
- `MITRE-ATT&CK-mapping.md` (technique classification and adversary behavior mapping)
- `detection-artifact-report.md` (identity, registry, and process execution artifacts)

**High-Level Summary Reference**  
A condensed overview of defensive gaps is provided in `windows-backdoor-account-registry-persistence-investigation.md` → **Detection and Hardening Opportunities**.  
This report expands those observations into detailed engineering and policy controls tied to specific investigation findings.

---

## Summary of Defensive Control Failures Observed

This section summarizes the primary control gaps that enabled persistent administrative access to be established on the compromised host.

Based on investigation findings, the following failures were confirmed:

- Windows Security Event ID 4720 (local user creation) occurred without alerting or approval workflows.
- Event IDs 4728 and 4732 (privileged group membership changes) were not correlated with new account creation.
- Registry autorun locations were modified without detection or change validation.
- WMIC and PowerShell execution occurred shortly after persistence establishment but were not correlated with identity changes.
- No automated containment actions were triggered following administrative privilege escalation.

As documented in the walkthrough timeline reconstruction, this allowed the attacker to:

1. Establish authenticated persistence via a backdoor account.
2. Maintain access across reboots using registry Run keys.
3. Execute follow-on commands using native administrative utilities.

---

## Identity and Account Management Hardening

This section focuses on preventing and detecting unauthorized account creation and privilege escalation on endpoints.

### Monitor and Restrict Local Account Creation

**Evidence from Investigation:**  
In the walkthrough, analysts pivoted to Security logs and filtered for account management events after observing suspicious execution behavior. Event ID 4720 revealed creation of an unauthorized local account that did not align with IT provisioning activity recorded in baseline host behavior.

**Recommendation:**

- Alert on Event ID 4720 on:
  - All workstations
  - Member servers not designated for user provisioning
- Require ticket-based or automated provisioning systems to tag legitimate account creation.
- Perform scheduled audits comparing local account lists to approved baselines.

**Security Impact:**  
Prevents attackers from quietly establishing authenticated persistence using newly created accounts.

### Detect and Control Administrative Group Membership Changes

**Evidence from Investigation:**  
The walkthrough documents that shortly after account creation, analysts identified Event IDs 4728 and 4732 showing the new account being added to local administrative groups, confirming immediate privilege escalation.

**Recommendation:**

- Alert when:
  - New accounts are added to local Administrators group
  - Privileged group changes occur outside approved change windows
- Correlate group changes with recent account creation events.

**Security Impact:**  
Detects escalation of privileges before attackers can establish persistence or deploy payloads.

---

## Registry Persistence Protection

This section focuses on preventing and detecting registry-based persistence mechanisms.

### Monitor Autorun Registry Locations

**Evidence from Investigation:**  
After identifying administrative privilege escalation, analysts pivoted to registry modification telemetry and identified changes to autorun paths under Run keys, configured to execute attacker-controlled commands at startup.

**Recommendation:**

- Alert on modifications to:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `RunOnce`
  - `Winlogon`
- Correlate with:
  - Recent account creation
  - Privileged group membership changes

**Security Impact:**  
Detects persistence establishment even when no malware binaries are dropped.

### Restrict Registry Modification Permissions

**Evidence from Investigation:**  
Registry changes were performed after the attacker obtained administrative privileges through group membership modification.

**Recommendation:**

- Limit which accounts can modify autorun registry paths.
- Enforce separation between:
  - Routine administration
  - Startup configuration management

**Security Impact:**  
Reduces the ability of compromised accounts to establish persistence.

---

## Administrative Tool Abuse Prevention

This section addresses misuse of legitimate Windows utilities such as WMIC and PowerShell for post-compromise activity.

### Monitor WMIC Execution

**Evidence from Investigation:**  
Process creation telemetry showed WMIC execution after persistence was established, suggesting follow-on activity or reconnaissance.

**Recommendation:**

- Alert on WMIC execution when:
  - Initiated by accounts created within the last N hours
  - Occurring on endpoints not designated for remote administration
- Disable WMIC where not operationally required.

**Security Impact:**  
Detects stealthy command execution and potential lateral movement staging.

### PowerShell Logging and Restriction

**Evidence from Investigation:**  
PowerShell was launched following WMIC usage, indicating progression to interactive or scripted post-compromise activity.

**Recommendation:**

- Enable:
  - Script Block Logging
  - Module Logging
- Apply Constrained Language Mode for non-administrative users.
- Alert on encoded or obfuscated command lines.

**Security Impact:**  
Limits attacker ability to leverage PowerShell for persistence and C2.

---

## Detection Engineering Improvements

This section focuses on building multi-stage behavioral detections.

### Correlate Account Creation → Privilege Escalation → Persistence

**Evidence from Investigation:**  
Timeline reconstruction in the walkthrough confirmed that account creation, group escalation, and registry persistence occurred sequentially within a short time window.

**Recommendation:**

Create SIEM correlations for:

1. Event ID 4720 (new account)
2. Event ID 4728 / 4732 (privileged group membership)
3. Registry autorun modification events

Trigger alerts when these events occur on the same host within defined thresholds.

**Security Impact:**  
Provides high-confidence detection of host compromise progression.

### Correlate Identity Changes with Administrative Tool Usage

**Evidence from Investigation:**  
WMIC and PowerShell were executed only after privilege escalation was achieved.

**Recommendation:**

- Alert when administrative tools are used by:
  - Accounts created within recent time thresholds
  - Accounts recently added to privileged groups

**Security Impact:**  
Detects post-compromise exploitation rather than benign administration.

---

## Endpoint Hardening and Privilege Management

This section focuses on limiting attacker capability even after credential compromise.

### Enforce Least Privilege on Workstations

**Evidence from Investigation:**  
Administrative privileges enabled registry modification and tool abuse.

**Recommendation:**

- Remove local admin rights where not operationally required.
- Implement Just-in-Time (JIT) privilege elevation for support tasks.

**Security Impact:**  
Prevents persistence mechanisms even when credentials are compromised.

### Harden Startup Configuration Controls

**Evidence from Investigation:**  
Persistence relied on autorun registry keys rather than services or tasks, but attackers often use multiple persistence layers.

**Recommendation:**

- Monitor:
  - Startup folders
  - Scheduled tasks
  - Services
- Baseline startup configurations across endpoints.

**Security Impact:**  
Detects alternative persistence mechanisms beyond registry keys.

---

## Logging and Telemetry Improvements

This section addresses visibility gaps observed during investigation.

### Expand Endpoint Telemetry Collection

**Evidence from Investigation:**  
Analysis relied primarily on Windows Security logs, limiting visibility into command-line arguments and registry value data.

**Recommendation:**

- Enable Sysmon or equivalent EDR telemetry for:
  - Process creation with full command line
  - Registry modification events
- Centralize logs into SIEM.

**Security Impact:**  
Improves fidelity of behavioral detections and investigation depth.

### Retain Identity and Registry Logs for Adequate Forensic Windows

**Evidence from Investigation:**  
Limited log retention constrains long-term compromise reconstruction.

**Recommendation:**

- Extend retention for:
  - Account management events
  - Registry modification events

**Security Impact:**  
Enables detection of low-and-slow persistence campaigns.

---

## Prioritized Recommendations

This table summarizes controls that would most effectively reduce risk based on behaviors observed in this incident.

| Priority | Area | Recommendation | Evidence Basis |
|--------|--------|----------------|----------------|
| High | Identity Monitoring | Alert on Event ID 4720 | Unauthorized account creation |
| High | Privilege Escalation | Monitor group membership changes | Immediate admin assignment |
| High | Persistence Detection | Monitor autorun registry keys | Run key modifications |
| High | Tool Abuse Detection | WMIC & PowerShell correlation | Post-persistence execution |
| Medium | Privilege Management | Enforce least privilege | Admin rights enabled persistence |
| Medium | Endpoint Telemetry | Enable registry & command logging | Limited investigation context |
| Low | Baseline Monitoring | Track startup configuration drift | Persistence alternatives |

---

## Closing Observations

This investigation demonstrates that attackers can achieve durable access using only native Windows features without deploying traditional malware.

As observed in this case:

- Persistence was achieved through identity and registry manipulation.
- Follow-on activity leveraged built-in administrative utilities.
- No external payloads were required.

Effective defense therefore requires:

- Strong monitoring of identity events on endpoints
- Visibility into startup configuration changes
- Correlation of administrative tool usage with account lifecycle events

Without cross-domain correlation between identity, registry, and process telemetry, attackers can maintain stealthy access using legitimate system functionality.
