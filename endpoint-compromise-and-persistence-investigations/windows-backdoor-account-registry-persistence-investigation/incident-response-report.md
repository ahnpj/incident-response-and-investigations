# Incident Response Report — Windows Host Compromise Investigation (Backdoor Account Creation and Registry-Based Persistence)

## Incident Classification

This section documents how the incident was categorized and prioritized based on confirmation of unauthorized account creation and registry-based persistence on a Windows host.

- **Incident Type:** Endpoint and Identity Compromise — Backdoor account with registry persistence  
- **Severity:** Critical (long-term unauthorized access and high risk of lateral movement)  
- **Status:** Contained  
- **Primary Impact Area:** Host integrity, identity trust, and persistence control

Classification is based on evidence reconstructed in `case-report.md` and validated in `windows-backdoor-account-registry-persistence-investigation.md`, including:

- Creation of an unauthorized local user account not associated with normal administrative workflows
- Registry modifications to ensure execution or access persistence across reboots
- Process and log artifacts confirming attacker interaction after initial compromise

This incident was categorized as **critical** because it demonstrates both **identity manipulation and persistence**, which significantly increases attacker dwell time and lateral movement risk.

---

## Detection Trigger

This section explains what initially indicated suspicious activity and why investigation was initiated.

Investigation was triggered by endpoint telemetry and log events indicating:

- New local account creation
- Registry modifications in autorun or persistence-related keys
- Follow-on process execution associated with newly created credentials

These signals warranted escalation because legitimate administrative activity rarely combines **account creation and persistence configuration** in the same workflow, especially outside approved provisioning systems.

For reconstructed attacker behavior sequence, see `case-report.md` → **Investigation Timeline**.  
For analyst pivot logic and validation steps, see `windows-backdoor-account-registry-persistence-investigation.md`.

---

## Initial Triage Actions

This section outlines how analysts confirmed unauthorized access, validated persistence, and assessed scope.

Triage focused on answering three questions:

### 1) Was the new account authorized or malicious?

Analysts reviewed:

- Security Event Logs for account creation events
- Local group membership for administrative privileges
- Change management and provisioning records

The account did not align with documented administrative provisioning processes, confirming unauthorized identity creation rather than routine IT activity.

### 2) Is persistence configured on the host?

Analysts pivoted to:

- Registry autorun locations
- User-specific and system-wide startup keys
- Task Scheduler and service configuration

Registry entries were identified that ensured execution or access continuity across reboots, confirming deliberate persistence mechanisms rather than transient exploitation.

### 3) Is there evidence of further attacker activity?

Analysts examined:

- Process execution following account creation
- Network connections associated with the new account
- Access to sensitive directories or tools

This scoping step was necessary to assess whether compromise extended beyond initial foothold into lateral movement or privilege escalation phases.

---

## Containment Actions

This section documents actions taken to immediately stop attacker access and prevent persistence from reactivating.

Containment prioritized **identity removal and host isolation**, as both credentials and system configuration were compromised.

### 1) Disable and Remove Backdoor Account

- **Immediately disable the unauthorized local account.**  
  *Why:* Prevents continued interactive or remote authentication using attacker-controlled credentials.

- **Remove account from administrative groups.**  
  *Why:* Ensures no residual privilege remains if the account is accidentally re-enabled or replicated elsewhere.

- **Audit for additional unauthorized accounts.**  
  *Why:* Attackers often create multiple backdoor identities to maintain redundancy.

### 2) Endpoint Isolation

- **Isolate affected system from the network.**  
  *Why:* Prevents lateral movement, credential harvesting, and command-and-control activity during eradication.

Isolation is required because persistence indicates attackers may return even if sessions are terminated.

### 3) Suspend Scheduled and Startup Execution Paths

- **Temporarily disable suspicious autorun mechanisms.**  
  *Why:* Prevents malicious code from executing during containment and eradication phases.

This prevents reactivation while forensic validation continues.

---

## Eradication Actions

This section documents steps taken to remove all persistence mechanisms and attacker-controlled access paths.

Eradication focused on fully restoring host trust.

### 1) Remove Registry Persistence

- Delete all unauthorized registry entries identified during investigation.  
  *Why:* Registry-based persistence ensures execution on reboot and must be fully removed to prevent reinfection.

- Validate no alternate autorun keys were modified.  
  *Why:* Attackers frequently implement multiple persistence methods to survive partial cleanup.

### 2) Credential and Privilege Review

- Reset credentials for:
  - Local administrator accounts
  - Users who authenticated on the host during compromise window

*Why:* Backdoor accounts can be used to harvest or reset other credentials, expanding blast radius.

### 3) Patch and Configuration Review

- Apply pending security updates.  
- Review endpoint hardening and account management policies.

*Why:* Prevents reuse of the same exploitation or misconfiguration pathways.

### 4) Consider Full System Reimage

- Reimage if:
  - Integrity cannot be confidently verified
  - Persistence scope is uncertain

*Why:* Full reimage is the most reliable way to remove deeply embedded persistence mechanisms.

---

## Recovery Actions

This section describes restoration of normal operations after eradication.

Recovery focused on restoring the host with verified clean configuration and access controls.

- Rejoin host to network only after eradication is complete.  
- Restore legitimate user access and verify administrative controls.  
- Re-enable startup services only after validation.

These steps ensure the system does not reintroduce malicious artifacts when returning to production.

---

## Validation and Post-Incident Monitoring

This section explains how remediation effectiveness was verified and what monitoring was applied.

Validation included:

- Confirming no re-creation of unauthorized accounts
- Verifying persistence-related registry keys remain unchanged
- Monitoring for abnormal authentication attempts from the affected host

Post-incident monitoring included:

- Alerts for new local account creation
- Alerts for modifications to autorun registry locations
- Monitoring for abnormal logon behavior across adjacent hosts

These controls help detect reinfection or lateral movement attempts early.

---

## Communication and Coordination

This section summarizes coordination between security, IT, and system owners.

Coordination included:

- Security teams leading investigation and forensic validation
- IT teams supporting account remediation and system reimaging
- Identity management teams reviewing account provisioning controls
- Management notified due to persistence and potential lateral movement risk

Cross-team coordination was required because the incident spanned both identity and endpoint security domains.

---

## Lessons Learned

This section captures defensive insights derived from this incident.

Key lessons include:

- Unauthorized account creation is a strong indicator of long-term attacker intent.
- Registry persistence should always be treated as high-severity compromise.
- Credential remediation must extend beyond the initially observed backdoor account.
- Endpoint reimaging remains the safest recovery method when persistence is confirmed.

These lessons informed hardening improvements documented in `detection-and-hardening-recommendations.md`.

---

## Related Documentation

- `windows-backdoor-account-registry-persistence-investigation.md` — analyst workflow and artifact validation  
- `case-report.md` — reconstructed attacker timeline and impact framing  
- `MITRE-ATT&CK-mapping.md` — technique classification and behavioral mapping  
- `incident-summary.md` — executive overview of incident and response  
- `detection-artifact-report.md` — identity and registry persistence artifacts  
- `detection-and-hardening-recommendations.md` — preventive and monitoring controls  
