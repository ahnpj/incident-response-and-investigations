# Endpoint Cryptominer Infection Investigation (Suspicious Process Execution and Resource Abuse)

**Category:** Endpoint Compromise and Persistence  
**Primary Attack Surface:** Local host execution environment  
**Tactics Observed:** Execution, Persistence, Resource Hijacking, Defense Evasion  
**Primary Data Sources:** Windows Security Event Logs, Sysmon Process Creation Events

---

### Overview

This investigation analyzes suspicious process execution detected by a SIEM, where the executable `cudominer.exe` was observed running on a Windows endpoint. The objective is to determine whether the activity represents benign user behavior or malicious resource abuse consistent with cryptocurrency mining.

The analysis focuses on validating the alert using correlated Windows process creation telemetry, user attribution, and execution path analysis to determine whether the detection represents a true security incident.

> 👉 **Follow the investigation walkthrough first**  
Begin with `investigation-walkthrough.md` inside an investigation folder to see how I identified, pivoted on, and validated evidence step by step.

> 👉 **Review findings and conclusions**  
Move to the `case-report.md` and `incident-summary.md` to understand what happened, what was confirmed, and why it mattered — from both technical and high-level perspectives.

> 👉 **Dig into evidence and detections**  
For deeper technical detail, review the `detection-artifact-report.md`, supporting screenshots, and extracted artifacts to see exactly how conclusions were supported by telemetry.

> 👉 **See defensive takeaways**  
Finish with `detection-and-hardening-recommendations.md` and `mitre-attack-mapping.md` to understand how observed attacker behavior maps to MITRE ATT&CK and where detection or control improvements were identified.

> 👉 **Use this repository as case-based learning**  
These investigations are designed to be read like **real SOC case files**, showing not just *what* happened, but *how* an analyst reasoned through the incident using multiple data sources.

---

### What This Investigation Covers

This case simulates a real-world scenario where an automated detection must be manually reviewed and classified. 

The investigation identifies the executable responsible for the alert (`cudominer.exe`), correlates the alert to Windows process creation events (Event ID 4688), attributes execution to user `Chris.Fort` on host `HR_02`, evaluates the execution path (`C:\Users\Chris.Fort\temp\cudominer.exe`) for risk, and reviews the SIEM detection rule to validate expected triggering behavior. 

Rather than relying on the alert alone, the walkthrough explains why specific log pivots were required, which event fields were used for attribution, and how execution context influenced final classification, reflecting how alert-driven investigations progress from detection to confirmation and response decision-making.

---

### How to Navigate This Investigation

This case is documented across multiple focused reports to reflect how incidents are handled in real SOC and incident response workflows. Supporting reports provide incident summaries, response actions, detection artifacts, and security improvement recommendations. A breakdown of each file is provided below.

If you want to follow the investigation step by step, start with:

**`investigation-walkthrough.md`**

---

### Repository Structure & Supporting Documents

All investigation outputs are separated into focused reports to reflect common incident documentation practices.

| File / Folder | Purpose | Contents and Focus |
|-------------|--------|--------------------|
| `investigation-walkthrough.md` | Structured alert validation workflow showing how a SIEM detection was correlated with endpoint telemetry to determine whether activity represented benign behavior or malicious resource abuse. | Documents review of alert metadata and triggering conditions, pivots from alert context to raw Windows process creation logs, attribution of execution to a specific user and endpoint, evaluation of executable naming and execution path legitimacy, and validation of detection rule behavior and final classification. Emphasizes evidence-based alert triage rather than reliance on alert labels alone. |
| `images/` | Visual evidence supporting analytical steps and conclusions documented in the reports. | Contains screenshots of original SIEM alert views, correlated Windows event logs, and detection rule configuration evidence that visually support each analytical step and conclusion. |
| `case-report.md` | Structured incident case record aligned with internal security case documentation formats. | Includes alert context, scope definition, evidence reviewed, and final classification decision in a format consistent with internal SOC case management records. |
| `detection-artifact-report.md` | Technical indicators and behavioral artifacts that can be converted into detections or hunts. | Documents executable naming patterns, execution path characteristics, and relevant Windows event fields suitable for translation into SIEM detection logic or threat hunting queries. |
| `incident-response-report.md` | Operational handling and response actions following confirmation of malicious activity. | Covers endpoint containment considerations, credential hygiene steps, and validation and cleanup guidance for post-incident remediation. |
| `incident-summary.md` | Executive-style overview for non-technical stakeholders. | Summarizes what occurred, why it matters, and recommended next actions to support communication with management, compliance, and IT leadership. |
| `detection-and-hardening-recommendations.md` | Endpoint monitoring and execution control improvements related to unauthorized process activity and resource abuse. | Includes recommendations for application allowlisting and execution restrictions, detection tuning for cryptocurrency mining indicators, monitoring of user-writable directory execution, resource utilization anomaly detection, and host-based isolation workflows following confirmed abuse, reflecting post-incident security improvement practices. |
| `MITRE-ATT&CK-mapping.md` | Behavioral mapping of observed activity to ATT&CK techniques for reporting and analysis. | Maps behaviors such as user execution of suspicious binaries and resource hijacking through unauthorized mining activity, using both narrative explanations and table-based technique mapping formats. |

---

### Environment, Data Sources, and Tools

This investigation focuses on validating suspicious software execution on a Windows endpoint using host-based process telemetry and artifact inspection to determine whether unauthorized cryptocurrency mining activity was present.

#### Environment and Investigation Scope (At a Glance)

| Area | Details |
|--------|---------|
| **Environment Type** | Windows endpoint (host-focused investigation) |
| **Affected Assets** | Windows workstation where suspicious executable launched from a user-writable directory |
| **Victim Operating System** | Windows workstation where suspicious or malicious execution occurred |
| **Analyst Operating System** | Windows-based analyst workstation used to query centralized logs and validate host artifacts |
| **Primary Platforms / Services** | Windows endpoint logging subsystem; Splunk SIEM platform |
| **Investigation Focus** | Validate suspicious execution as cryptominer-like activity using host telemetry and artifact confirmation |

#### Data Sources, Evidence, and Analysis Techniques

| Area | Details |
|--------|---------|
| **Primary Telemetry Sources** | Windows Security Event Logs (Event ID 4688 — Process Creation), including executable names, file paths, command-line arguments, parent-child process relationships, host identity fields, and associated user context |
| **Host Identity and User Context** | Hostname and user account fields used to attribute execution events to specific endpoints and logged-in users |
| **File Path and Naming Artifacts** | Executable names and directory locations reviewed to assess alignment with known cryptominer and dropper behavior, including execution from temporary or user-writable directories |
| **Evidence Types Reviewed** | Process execution patterns, command-line context, process lineage, executable placement, and indicators consistent with unauthorized resource consumption |
| **Splunk Analysis Techniques** | SPL queries used to filter Event ID 4688 events, identify rare or suspicious executable names, pivot across host and user fields, and scope potential repeat or spread of execution activity |
| **Host Validation Techniques** | Local file system inspection to confirm executable placement and validate absence of legitimate installation paths |
| **Malware Assessment Heuristics** | Behavioral evaluation based on executable naming conventions, execution location, and potential indicators of sustained CPU utilization |
| **Operational Workflow Context** | Demonstrates rapid endpoint triage workflows used by SOC analysts to validate suspicious execution alerts prior to escalation to full malware response procedures |

This investigation demonstrates rapid endpoint triage workflows used by SOC analysts to validate suspicious execution alerts before escalating to full malware response procedures.

---

### Intended Use

This investigation demonstrates structured alert analysis, log correlation, and evidence-based classification using endpoint telemetry and SIEM detections. It is designed to reflect how suspicious execution events are validated, documented, and translated into detection and response improvements.

---

### Relevance to Security Operations

Unauthorized process execution remains a common initial indicator of compromise or misuse.

This investigation demonstrates how centralized logging enables analysts to:

- Validate detections using endpoint telemetry
- Attribute activity to specific users and systems
- Identify execution behaviors that warrant containment

Even single-event alerts benefit from systematic investigation to avoid misclassification and to support appropriate response actions.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation is intended to demonstrate practical alert analysis, log correlation methodology, and professional incident documentation aligned with real operational workflows.





