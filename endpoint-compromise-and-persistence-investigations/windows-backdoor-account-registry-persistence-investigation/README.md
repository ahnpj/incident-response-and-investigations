# Windows Host Compromise Investigation (Backdoor Account Creation and Registry-Based Persistence)

**Category:** Endpoint Compromise and Persistence  
**Primary Attack Surface:** Local accounts and registry autorun mechanisms  
**Tactics Observed:** Persistence, Privilege Escalation, Account Manipulation, Defense Evasion  
**Primary Data Sources:** Windows Security Event Logs (Account & Group Changes), Sysmon Registry Events

---

### Overview

This investigation analyzes a Windows host compromise involving unauthorized local account creation, registry modifications tied to account persistence, and follow-on encoded PowerShell execution with outbound communication.

The objective is to reconstruct attacker behavior using correlated Windows Security, Sysmon registry, and PowerShell telemetry to determine how the backdoor account was created, whether impersonation was attempted, and how post-compromise activity was executed. The analysis validates account creation and privilege changes, confirms registry-based persistence mechanisms, and reconstructs encoded scripting activity to identify outbound communication associated with attacker-controlled infrastructure.

> 👉 **Follow the investigation walkthrough first**  
Begin with `investigation-walkthrough.md` inside this investigation folder to see how I identified, pivoted on, and validated evidence step by step.

> 👉 **Review findings and conclusions**  
Move to the `case-report.md` and `incident-summary.md` to understand what happened, what was confirmed, and why it mattered — from both technical and high-level perspectives.

> 👉 **Dig into evidence and detections**  
For deeper technical detail, review the `detection-artifact-report.md`, supporting screenshots, and extracted artifacts to see exactly how conclusions were supported by telemetry.

> 👉 **See defensive takeaways**  
Finish with `detection-and-hardening-recommendations.md` and `mitre-attack-mapping.md` to understand how observed attacker behavior maps to MITRE ATT&CK and where detection or control improvements were identified.

> 👉 **See what each investigation file contains in full detail**  
For a complete breakdown of every standard file in an investigation folder, explaining the contents, intent, and role of each document in the overall case, see the **[Repository Structure & Supporting Documents](#repository-structure--supporting-documents)** section below

---

### What This Investigation Covers

This case simulates post-incident log analysis following detection or escalation involving abnormal account and scripting activity on a Windows endpoint.

The investigation identifies suspicious use of `net user /add` to create a local account, confirms account creation using Windows Security Event ID **4720**, correlates registry artifacts under the SAM hive confirming account registration, and evaluates impersonation intent by comparing look-alike usernames (`Alberto` vs `A1berto`). It also confirms remote execution via **WMIC**, evaluates whether the backdoor account was used for authentication, identifies the host executing encoded PowerShell, and decodes a multi-layer Base64 payload to extract a full outbound URL.

Rather than relying on a single telemetry source, the walkthrough emphasizes correlation across identity, registry, execution, and scripting logs to build a complete narrative of attacker persistence and post-compromise activity.

---

### How to Navigate This Investigation

This case is documented across multiple focused reports to reflect how incidents are handled in real SOC and incident response workflows. Supporting reports provide incident summaries, response actions, detection artifacts, and security improvement recommendations. A breakdown of each file is provided below.

If you want to follow the investigation step by step, start with:

**`investigation-walkthrough.md`**

---

### Repository Structure & Supporting Documents

All investigation outputs are separated into focused reports aligned with common incident documentation practices.

| File / Folder | Purpose | Contents and Focus |
|-------------|--------|--------------------|
| `investigation-walkthrough.md` | Forensic-style log analysis walkthrough focused on identifying account-based persistence and follow-on scripting activity on a Windows host. | Documents identification of unauthorized account creation via command-line and event telemetry, correlation of Security Event ID 4720 with process execution evidence, registry artifact confirmation under SAM hive paths, detection of impersonation through look-alike usernames, identification of remote execution via WMIC, reconstruction and decoding of encoded PowerShell commands, and extraction of outbound communication destinations. Emphasizes cross-correlation of identity, registry, execution, and scripting telemetry. |
| `images/` | Visual evidence supporting analytical steps and conclusions documented in the reports. | Contains screenshots and log excerpts showing command-line and account creation evidence, registry artifact confirmation under the SAM hive, WMIC remote execution telemetry, and PowerShell decoding and outbound destination extraction. |
| `case-report.md` | Primary technical record of the investigation aligned with internal security case documentation formats. | Summarizes investigation scope, evidence sources and telemetry reviewed, host and account attribution, and final incident determination for tracking, escalation, and post-incident review. |
| `detection-artifact-report.md` | Detection-relevant behaviors associated with account creation, registry modification, and scripted follow-on activity. | Documents command-line indicators, SAM hive registry paths, WMIC execution patterns, and encoded PowerShell behaviors suitable for SIEM correlation searches, endpoint detection rules, and threat hunting queries. |
| `incident-response-report.md` | Operational actions required to remove attacker-established persistence and prevent continued access. | Covers backdoor account removal and credential remediation, host isolation and validation steps, registry cleanup considerations, and short-term monitoring recommendations following confirmation of account-based persistence. |
| `incident-summary.md` | Executive-level overview of unauthorized persistence established on a Windows host. | Summarizes how persistence was introduced, potential business and security impact, and why the activity required incident response without exposing technical investigation detail. |
| `detection-and-hardening-recommendations.md` | Security control improvements identified through analysis of identity, registry, and scripting activity. | Includes recommendations covering restrictions on local account creation and privilege assignment, registry auditing and tamper protection for SAM hive paths, governance of remote administration tools such as WMIC, PowerShell logging and script execution policy improvements, and monitoring strategies for persistence-related behaviors. |
| `MITRE-ATT&CK-mapping.md` | Behavioral mapping of observed activity to MITRE ATT&CK tactics and techniques. | Maps account manipulation, registry modification, remote execution, and scripting activity to ATT&CK techniques using Windows Security, Sysmon/registry, and PowerShell telemetry, with both narrative explanations and table-based mappings. |

---

### Environment, Data Sources, and Tools

This investigation analyzes post-compromise host activity involving unauthorized local account creation and registry-based persistence mechanisms using centralized endpoint telemetry and manual artifact validation.

#### Environment and Investigation Scope (At a Glance)

| Area | Details |
|--------|---------|
| **Environment Type** | Windows workstation (persistence and account manipulation case) |
| **Affected Assets** | Local accounts and administrative group membership, registry autorun persistence locations, and related file artifacts |
| **Victim Operating System** | Windows workstation where attacker-created user accounts and startup persistence mechanisms were configured |
| **Analyst Operating System** | Windows-based analyst workstation used to query SIEM telemetry, decode artifacts, and validate host configuration |
| **Primary Platforms / Services** | Windows local authentication and group management services; Windows registry autorun mechanisms; Splunk SIEM platform |
| **Investigation Focus** | Confirm backdoor account establishment, validate registry persistence, and reconstruct post-compromise execution activity |

#### Data Sources, Evidence, and Analysis Techniques

| Area | Details |
|--------|---------|
| **Primary Telemetry Sources** | Windows Security Event Logs (Event IDs 4720 and 4732) and Sysmon operational logs capturing account creation, privilege changes, registry value creation, process execution, and file creation |
| **Host Identity and User Context** | Hostname and user account fields used to attribute persistence mechanisms and execution events to specific systems and identities |
| **Registry Persistence Artifacts** | SAM hive and autorun registry paths reviewed to validate account registration and startup execution configuration |
| **File System Artifacts** | Executable placement and timestamp correlation reviewed to confirm persistence-related file activity |
| **Splunk Analysis Techniques** | SPL queries used to filter on account and registry event IDs, pivot across host, user, and process fields, and reconstruct a timeline of attacker actions |
| **CyberChef Usage** | Decoding and normalization of encoded registry values and command-line strings extracted from event logs |
| **PowerShell Validation** | Enumeration of startup registry keys, validation of file paths referenced by persistence entries, and confirmation of attacker-created user accounts |
| **Administrative Tooling** | Inspection of local user and group configuration and validation of file system artifacts referenced by persistence mechanisms |
| **Operational Workflow Context** | Demonstrates host-based post-exploitation validation techniques used to confirm persistence and privilege escalation following initial access |

This investigation demonstrates host-based post-exploitation validation techniques commonly used to confirm persistence and privilege escalation following initial access.

---

### Intended Use

This investigation demonstrates structured post-compromise log analysis, artifact correlation, and evidence-based classification of account-based persistence using endpoint telemetry and SIEM detections. It reflects how abnormal identity and registry activity is validated, documented, and translated into response and detection improvement actions.

---

### Relevance to Security Operations

Account-based persistence remains a common method for maintaining long-term access to compromised systems.

This investigation demonstrates how centralized logging enables analysts to validate identity manipulation, confirm registry-based startup mechanisms, and correlate scripting activity with outbound communication to assess ongoing risk.

Systematic correlation across identity, registry, and execution telemetry supports accurate classification, containment decisions, and long-term detection improvements.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation is intended to demonstrate practical post-compromise analysis, cross-source log correlation, and professional incident documentation aligned with real operational workflows.



