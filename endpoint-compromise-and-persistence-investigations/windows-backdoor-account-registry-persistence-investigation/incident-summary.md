# Incident Summary — Windows Host Compromise Investigation (Backdoor Account Creation and Registry-Based Persistence)

## Overview

This incident involved the creation of an unauthorized local backdoor account on a Windows host, followed by the establishment of registry-based persistence and attempted remote command execution using built-in administrative tools.

The attacker leveraged legitimate Windows utilities to maintain access, escalate control, and attempt follow-on activity, consistent with living‑off‑the‑land tradecraft rather than the deployment of traditional malware.

---

## What Happened

This section summarizes the confirmed attacker activity and how control of the host was established and maintained.

Investigation confirmed that an attacker created a new local user account and added it to privileged groups, providing persistent access to the system. Shortly after account creation, registry keys were modified to ensure execution of attacker-controlled commands at system startup or user logon.

Following establishment of persistence, the attacker attempted to execute commands remotely using Windows Management Instrumentation Command-line (WMIC) and later launched PowerShell for interactive command execution and potential command-and-control behavior.

The activity sequence indicates deliberate post-compromise actions rather than accidental misconfiguration or user error.

### Timeline References

Two complementary timelines are documented across supporting reports:

- **Attack and impact timeline:** Documented in `case-report.md` under **Investigation Timeline**, which reconstructs account creation, registry modification, and remote execution attempts in chronological order.
- **Analyst investigation workflow:** Documented in `windows-backdoor-account-registry-persistence-investigation.md`, which details how logs were analyzed, how pivots were selected, and how artifacts were validated during response.

This separation reflects standard SOC practice of distinguishing attacker behavior from investigative process.

---

## Impact

This section describes the confirmed and potential impact of the compromise on system integrity and organizational risk.

The creation of a privileged backdoor account represents full administrative compromise of the host, allowing attackers to:

- Authenticate persistently
- Execute arbitrary commands
- Modify security controls
- Deploy additional payloads

Registry-based persistence further ensured that malicious activity could resume after system reboots or user logoff events.

Although no data exfiltration or lateral movement was confirmed during this investigation, the attacker achieved sufficient access to pivot to other systems if the compromise had remained undetected.

### Impact Documentation References

- Privileged group membership and account creation evidence is documented in `case-report.md` and validated in the walkthrough.
- Persistence mechanisms and registry keys are detailed in `windows-backdoor-account-registry-persistence-investigation.md`.
- Technique classification is documented in `MITRE-ATT&CK-mapping.md` under **Persistence** and **Privilege Escalation** tactics.

---

## How It Was Detected

This section explains what security signals led to discovery of the compromise and initiation of host-based investigation.

Detection was driven by abnormal user and process activity observed in Windows event logs, including:

- Creation of a new local user account
- Addition of that account to administrative groups
- Execution of WMIC and PowerShell shortly after account creation

These events triggered suspicion of unauthorized administrative activity rather than routine IT operations.

Correlation of identity and process telemetry highlighted a sequence consistent with attacker persistence establishment rather than benign configuration changes.

---

## Response Summary

This section summarizes the high-level actions taken to contain and remediate the compromise.

Response actions focused on:

- Disabling and removing the unauthorized backdoor account
- Removing registry-based persistence mechanisms
- Investigating additional systems for related activity
- Resetting credentials for affected users
- Restoring system configuration to known-good state

No evidence of further propagation or secondary payload deployment was identified following remediation.

Detailed response procedures are documented in `incident-response-report.md`.

---

## Next Steps and Prevention

This section summarizes recommended actions to prevent recurrence of similar host-based compromises.

Preventive focus areas include:

- Monitoring for unauthorized account creation and group membership changes
- Detection of registry-based persistence techniques
- Restricting administrative tool misuse such as WMIC and PowerShell
- Improving host-based intrusion detection and alert correlation

High-level defensive gaps are summarized in the investigation walkthrough, while detailed engineering and policy controls are documented in:

- `detection-and-hardening-recommendations.md`

---

## Related Documentation

This section lists supporting reports that provide technical investigation detail, response actions, and long-term remediation guidance.

- `windows-backdoor-account-registry-persistence-investigation.md` — analyst workflow, log pivots, and validation steps  
- `case-report.md` — incident timeline and evidentiary conclusions  
- `MITRE-ATT&CK-mapping.md` — technique classification and behavioral mapping  
- `detection-artifact-report.md` — detection-relevant log fields and behavioral indicators  
- `detection-and-hardening-recommendations.md` — preventive controls and monitoring improvements  
- `incident-response-report.md` — containment, eradication, recovery, and monitoring actions
