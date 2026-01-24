# Windows Host Compromise Investigation (Backdoor Account Creation and Registry-Based Persistence)

**Category:** Endpoint Compromise and Persistence  
**Primary Attack Surface:** Local accounts and registry autorun mechanisms  
**Tactics Observed:** Persistence, Privilege Escalation, Account Manipulation, Defense Evasion  
**Primary Data Sources:** Windows Security Event Logs (Account & Group Changes), Sysmon Registry Events

This investigation analyzes a Windows host compromise involving unauthorized local account creation, registry modifications tied to account persistence, and follow-on encoded PowerShell execution with outbound communication.

The analysis focuses on reconstructing attacker behavior using Windows Security, Sysmon/registry, and PowerShell telemetry to determine how the backdoor account was created, whether impersonation was attempted, and how post-compromise activity was executed.

The investigation demonstrates how an analyst:
- Identifies backdoor account creation using command-line and account management logs
- Correlates registry artifacts associated with new local users
- Detects impersonation attempts using look-alike usernames
- Reconstructs encoded PowerShell execution and outbound communication

---

## What This Investigation Covers

This case simulates post-incident log analysis following suspicious behavior on a Windows endpoint. The dataset is treated as if it were received after a detection or escalation involving abnormal account and scripting activity.


The investigation walks through how the analyst:

- Identifies suspicious use of `net user /add` to create a local account
- Confirms account creation using Windows Security Event ID **4720**
- Correlates registry artifacts under the SAM hive confirming account registration
- Determines impersonation intent by comparing usernames (`Alberto` vs `A1berto`)
- Confirms remote execution via **WMIC** rather than local interactive login
- Evaluates whether the backdoor account was used for authentication
- Identifies the host executing encoded PowerShell
- Decodes a multi-layer Base64 payload to extract a full outbound URL

Rather than relying on a single data source, the walkthrough emphasizes \*\*correlation across log types\*\* to build a complete narrative of attacker activity.

---

## Environment, Data Sources, and Tools

This investigation analyzes post-compromise host activity involving unauthorized local account creation and registry-based persistence mechanisms using centralized endpoint telemetry and manual artifact validation.

### At-a-Glance Summary

| Area | Details |
|------|---------|
| **Environment Type** | Windows workstation (persistence + account manipulation case) |
| **Affected Assets** | Local accounts + administrative group membership; registry autorun persistence locations; related file artifacts |
| **Primary Platforms / Services** | Windows local authentication + group management services; Windows registry autorun mechanisms; Splunk SIEM platform |
| **Telemetry Sources Reviewed** | Windows Security Event Logs (via Splunk); Sysmon Operational Logs (via Splunk); registry persistence artifacts; file system artifacts |
| **Evidence Types** | Unauthorized account creation and privilege changes; registry-based startup/persistence indicators; supporting file artifacts tied to persistence |
| **Tools Used** | Splunk (SPL queries for account + registry pivots); CyberChef (artifact decoding/normalization when needed); PowerShell (validation/enrichment steps documented in lab); built-in Windows admin tooling (local users/groups + registry review) |
| **Investigation Focus** | Confirm backdoor account establishment + registry persistence and trace how access was maintained |

### Operating Systems

- **Affected System (Victim Environment):**  
  Windows workstation where attacker-created user accounts and startup persistence mechanisms were configured.

- **Analyst Environment:**  
  Windows-based analyst workstation used to query SIEM telemetry, decode artifacts, and validate host configuration.

### Platforms and Services

- **Windows Local Authentication and Group Management Services**  
  Generated security events related to user account creation and administrator group membership changes.

- **Windows Registry Autorun Mechanisms**  
  Provided startup execution points abused for persistence following account creation.

- **Splunk SIEM Platform**  
  Used to correlate Windows Security and Sysmon telemetry to reconstruct attacker behavior across account manipulation and persistence stages.

### Data Sources Reviewed

- **Windows Security Event Logs (via Splunk)**  
  Reviewed to identify:
  - Local user account creation events (Event ID 4720)
  - Administrator group membership additions (Event ID 4732)
  - Timeline correlation between account creation and privilege escalation

- **Sysmon Operational Logs (via Splunk)**  
  Reviewed to identify:
  - Process execution associated with persistence setup
  - Registry value creation in autorun locations
  - File creation events tied to dropped binaries

- **Registry Persistence Artifacts**  
  Examined to validate:
  - Autorun key locations
  - Executable paths launched at startup

- **File System Artifacts**  
  Reviewed to confirm:
  - Executable placement
  - Timestamp correlation with persistence events

### Tools and Analysis Techniques

- **Splunk (SPL Queries)**  
  Used to:
  - Filter on specific event IDs related to account and registry changes
  - Pivot across host, user, and process fields
  - Reconstruct a timeline of attacker actions

- **CyberChef**  
  Used to decode and normalize:
  - Encoded registry values
  - Command-line strings extracted from event logs

- **PowerShell**  
  Used to:
  - Enumerate startup registry keys
  - Validate file paths referenced by persistence entries
  - Confirm existence of attacker-created user accounts

- **Built-In Windows Administrative Tools**  
  Used to inspect:
  - Local user and group configuration
  - File system artifacts referenced by persistence mechanisms

This investigation demonstrates host-based post-exploitation validation techniques commonly used to confirm persistence and privilege escalation following initial access.



---

## Repository Structure & Supporting Documents

All investigation outputs are separated into focused reports aligned with common incident documentation practices.

### `investigation-walkthrough.md`

Provides a forensic-style log analysis walkthrough focused on identifying account-based persistence and follow-on scripting activity on a Windows host.

The walkthrough documents:

- Identification of unauthorized account creation via command-line and event telemetry  
- Correlation of Security Event ID 4720 with process execution evidence  
- Registry artifact confirmation under SAM hive paths  
- Detection of impersonation through look-alike usernames  
- Identification of remote execution via WMIC  
- Reconstruction and decoding of encoded PowerShell commands  
- Extraction of outbound communication destinations  

The walkthrough emphasizes cross-correlation of identity, registry, execution, and scripting telemetry to build a complete persistence narrative.


### `images`

Contains screenshots and log excerpts referenced throughout the investigation, including:

- Command-line and account creation evidence  
- Registry artifact confirmation under the SAM hive  
- WMIC remote execution telemetry  
- PowerShell decoding and outbound destination extraction  

These images provide visual validation of investigative steps and support all technical conclusions documented in the reports.

### `case-report.md`

Provides the primary technical record of the investigation, documenting how the backdoor account, registry artifacts, and follow-on PowerShell activity were identified and correlated.

Summarizes:

- Investigation scope  
- Evidence sources and telemetry reviewed  
- Host and account attribution  
- Final incident determination  

Written in the style of formal security case documentation used for tracking, escalation, and post-incident review.


### `detection-artifact-report.md`

Documents detection-relevant behaviors associated with account creation, registry modification, and scripted follow-on activity observed during the intrusion.

Includes artifacts suitable for:

- SIEM correlation searches  
- Endpoint detection rules  
- Threat hunting queries  

Focuses on command-line indicators, SAM hive registry paths, WMIC execution patterns, and encoded PowerShell behaviors that can support early detection of similar persistence techniques.


### `incident-response-report.md`

Focuses on operational actions required to remove attacker-established persistence and prevent continued access to affected systems.

Includes:

- Backdoor account removal and credential remediation  
- Host isolation and validation steps  
- Registry cleanup considerations  
- Short-term monitoring recommendations  

Reflects how response teams document eradication and recovery actions following confirmation of account-based persistence.


### `incident-summary.md`

Provides a concise, executive-level overview of unauthorized persistence established on a Windows host through backdoor account creation and follow-on scripting activity.

Intended for:

- Management  
- IT leadership  
- Compliance and audit stakeholders  

Summarizes how persistence was introduced, potential business and security impact, and why the activity required incident response without exposing technical investigation detail.


### `detection-and-hardening-recommendations.md`

Focuses on security control improvements identified through analysis of identity, registry, and scripting activity associated with the compromise.

Includes recommendations covering:

- Restrictions on local account creation and privilege assignment  
- Registry auditing and tamper protection for SAM hive paths  
- Governance of remote administration tools such as WMIC  
- PowerShell logging and script execution policy improvements  
- Monitoring strategies for persistence-related behaviors  

This file reflects how security teams document detection improvements and system hardening actions following confirmation of host-based persistence techniques.


### `MITRE-ATT&CK-mapping.md`

Maps observed account manipulation, registry modification, remote execution, and scripting activity to MITRE ATT&CK tactics and techniques using evidence derived from Windows Security, Sysmon/registry, and PowerShell telemetry.

Includes:

- MITRE ATT&CK tactics and techniques  
- Evidence excerpts supporting each mapped behavior  

Both narrative explanations and a table view are provided to support standardized reporting, detection validation, and alignment with threat modeling frameworks.

---