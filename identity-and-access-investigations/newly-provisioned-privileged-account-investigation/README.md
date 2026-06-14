# Newly Provisioned Privileged Account Investigation

**Category:** Identity and Access Investigations  
**Primary Attack Surface:** Windows account management, authentication, and authorization activity  
**Tactics Observed:** Persistence, Privilege Escalation, Defense Evasion  
**Primary Data Sources:** Windows Security Event Logs (EVTX), Account Management Events, Security Group Management Events, Authentication Events

---

### Overview

This investigation analyzes suspicious administrative account activity identified through Windows Security Event Log monitoring. The investigation began after security monitoring detected administrator account logons occurring outside an employee's expected working schedule, including activity observed during times when the employee was not expected to be working.

Analysis of the provided Windows Security Event Log export revealed that the administrator account under review created a new user account, assigned the account to multiple security groups including the local Administrators group, and that the newly provisioned account subsequently authenticated using elevated privileges.

The investigation focuses on reconstructing identity and access activity using Windows Security Event Logs to determine how the account was created, what permissions were assigned, how privileges were granted, and whether the account was subsequently used.

> 👉 **Follow the investigation walkthrough first**  
Begin with `investigation-walkthrough.md` inside this investigation folder to see how I identified, correlated, and validated evidence step by step using Windows Security Event Logs.

> 👉 **Review findings and conclusions**  
Move to the `case-report.md` and `incident-summary.md` to understand what activity was identified, what was validated through event correlation, and why the findings warranted further review.

> 👉 **Dig into evidence and detections**  
For deeper technical detail, review the `detection-artifact-report.md`, supporting screenshots, and extracted event data to see exactly how conclusions were supported by Windows Security Event Log evidence.

> 👉 **See defensive takeaways**  
Finish with `detection-and-hardening-recommendations.md` and `mitre-attack-mapping.md` to understand how the observed account lifecycle activity maps to MITRE ATT&CK and where detection opportunities were identified.

> 👉 **See what each investigation file contains in full detail**  
For a complete breakdown of every standard file in an investigation folder, explaining the contents, intent, and role of each document in the overall case, see the **[Repository Structure & Supporting Documents](#repository-structure--supporting-documents)** section below.

The investigation demonstrates how an analyst:

- Reviews Windows Security Event Logs to validate suspicious authentication activity
- Identifies account creation and account management events
- Correlates user creation, privilege assignment, and authentication activity
- Reconstructs an account lifecycle using Windows Security Event IDs
- Evaluates suspicious administrative behavior using identity and access telemetry

---

### What This Investigation Covers

This case simulates a real-world identity and access investigation triggered by anomalous administrator logon activity. During review of the Windows Security Event Logs, the investigation expanded beyond authentication analysis and revealed a complete account provisioning workflow involving account creation, security group assignment, administrative privilege allocation, and subsequent account usage.

The walkthrough explains why specific Event IDs were reviewed, how investigative pivots were selected, and what evidence supports each finding. This mirrors how a SOC analyst or incident responder would investigate suspicious account activity using native Windows logging rather than endpoint malware artifacts or network telemetry.

---

### How to Navigate This Investigation

This case is documented across multiple focused reports to reflect how identity and access investigations are handled in real SOC and incident response workflows. Supporting reports provide investigation summaries, evidence analysis, detection opportunities, and defensive recommendations. A breakdown of each file is provided below.

If you want to follow the investigation step by step, start with:

**`investigation-walkthrough.md`**

---

### Repository Structure & Supporting Documents

All investigation outputs are intentionally separated into focused reports, similar to how SOC case management and incident response documentation is often organized in real environments.

| File / Folder | Purpose | Contents and Focus |
|-------------|--------|--------------------|
| `investigation-walkthrough.md` | Detailed analytical narrative reconstructing account creation, privilege assignment, and authentication activity using Windows Security Event Logs. | Documents chronological review of Windows Security events, Event ID filtering, authentication analysis, account creation validation, security group membership review, account lifecycle reconstruction, and correlation of administrative activity. Explains why specific Event IDs were reviewed, how investigative pivots were chosen, and how conclusions were derived from observable log evidence. |
| `images/` | Visual evidence supporting analytical steps and conclusions documented in the reports. | Contains screenshots from Event Viewer, Event ID filters, account creation events, security group assignments, authentication events, and timeline reconstruction artifacts used to validate findings. |
| `case-report.md` | Primary technical record of the investigation, aligned with SOC case documentation formats. | Summarizes investigation scope, evidence sources, key findings, event chronology, and final determination regarding account provisioning and privileged account usage. |
| `detection-artifact-report.md` | Detection-relevant technical artifacts derived from authentication and account management activity. | Includes Windows Security Event IDs, account creation events, security group changes, privileged authentication events, and correlation opportunities suitable for SIEM detections and threat hunting. |
| `incident-response-report.md` | Operational response actions required to validate, contain, and remediate suspicious account activity. | Covers account validation procedures, privilege review, account disablement considerations, escalation guidance, and short-term monitoring recommendations. |
| `incident-summary.md` | Executive-level overview written for stakeholders requiring situational awareness without deep technical detail. | Summarizes the original anomaly, investigative findings, business impact considerations, and final investigative outcome. |
| `detection-and-hardening-recommendations.md` | Preventive controls and monitoring improvements identified through analysis of account creation and privilege assignment activity. | Includes recommendations covering account management controls, privileged access monitoring, Event ID alerting, access governance improvements, and logging enhancements. |
| `mitre-attack-mapping.md` | Behavioral mapping of observed activity to MITRE ATT&CK tactics and techniques using Windows Security Event evidence. | Includes mapped techniques with supporting event evidence presented in both narrative and table format to support reporting, threat modeling, and detection engineering. |

---

### Environment, Data Sources, and Tools

This investigation focuses on identity and access activity recorded within Windows Security Event Logs rather than endpoint malware execution, memory forensics, or network-based compromise indicators. All analysis was performed using native Windows logging and Event Viewer.

#### Environment and Investigation Scope (At a Glance)

| Area | Details |
|------|---------|
| **Environment Type** | Windows endpoint / Windows administrative account activity investigation |
| **Affected Assets** | Windows user accounts, security groups, and authentication activity |
| **Victim Operating System** | Windows |
| **Analyst Operating System** | Windows |
| **Primary Platforms / Services** | Windows Security Event Logging, Event Viewer |
| **Investigation Focus** | Administrative account activity, account provisioning, privilege assignment, and authentication events |

#### Data Sources, Evidence, and Analysis Techniques

| Area | Details |
|------|---------|
| **Primary Telemetry Sources** | Windows Security Event Logs (`Security Investigation.evtx`) |
| **Authentication Evidence** | Event ID 4624 (Successful Logon), Event ID 4672 (Special Logon) |
| **Account Management Evidence** | Event ID 4720 (User Account Creation) |
| **Group Membership Evidence** | Event ID 4732 (Security Group Membership Changes) |
| **Event Viewer Usage** | Review of Windows Security Event Logs, event properties, filtering, and timeline reconstruction |
| **Filtering Techniques** | Event ID filtering, chronological sorting, event correlation, account activity reconstruction |
| **Timeline Analysis** | Correlation of authentication, account creation, and privilege assignment activity to establish account lifecycle events |
| **Operational Workflow Context** | Demonstrates how suspicious identity activity can be investigated using native Windows logging without requiring endpoint forensic artifacts or SIEM-only telemetry |

Each tool and technique was selected to reflect common SOC and incident response workflows when investigating suspicious account activity using Windows-native logging sources.

---

### Intended Use

This investigation demonstrates structured Windows Security Event Log analysis for an identity and access investigation. It reflects how suspicious administrative activity, account provisioning, privilege assignment, and authentication behavior can be validated, documented, and translated into response actions and longer-term detection improvements.

---

### Relevance to Security Operations

Identity and access activity remains one of the most important sources of investigative evidence in modern environments because legitimate administrative actions can closely resemble malicious activity. New account creation, privilege assignment, and privileged authentication events frequently appear during insider threat investigations, account compromise investigations, privilege escalation cases, and persistence-related incidents.

This investigation demonstrates how Windows Security Event Logs can be used to reconstruct account lifecycles, validate administrative activity, identify suspicious account provisioning behavior, and develop detection opportunities that improve visibility into identity and access-related threats.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation is intended to demonstrate structured analytical thinking, Windows Security Event Log analysis, evidence correlation, timeline reconstruction, and professional investigation documentation aligned with real SOC and incident response workflows.