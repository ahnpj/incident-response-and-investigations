# Endpoint Cryptominer Infection Investigation (Suspicious Process Execution and Resource Abuse)

**Category:** Endpoint Compromise and Persistence  
**Primary Attack Surface:** Local host execution environment  
**Tactics Observed:** Execution, Persistence, Resource Hijacking, Defense Evasion  
**Primary Data Sources:** Windows Security Event Logs, Sysmon Process Creation Events

This investigation analyzes suspicious process execution detected by a SIEM, where the executable `cudominer.exe` was observed running on a Windows endpoint. The objective is to determine whether the activity represents benign user behavior or malicious resource abuse consistent with cryptocurrency mining.

The analysis focuses on validating the alert using correlated Windows process creation telemetry, user attribution, and execution path analysis to determine whether the detection represents a true security incident.

The investigation demonstrates how an analyst:
- Validates what triggered an automated detection
- Attributes execution to a specific user and endpoint
- Evaluates execution paths for legitimacy
- Confirms whether detection logic behaved as intended

---

## What This Investigation Covers

This case simulates a real-world scenario in which an automated detection must be manually reviewed and classified.

The investigation walks through how the analyst:

- Identifies the executable responsible for the alert (`cudominer.exe`)
- Correlates the alert to **Windows process creation events (Event ID 4688)**
- Attributes execution to the user **Chris.Fort** on host **HR_02**
- Reviews the execution path (`C:\Users\Chris.Fort\temp\cudominer.exe`) to assess risk
- Examines the SIEM detection rule to validate expected triggering behavior

Rather than relying on the alert alone, the walkthrough explains:

- **Why specific log pivots were required**
- **Which event fields were used for attribution**
- **How execution context influenced classification**

This reflects how alert-driven investigations progress from detection to confirmation and response decision-making.

---

## Environment, Data Sources, and Tools

This investigation focuses on validating suspicious software execution on a Windows endpoint using host-based process telemetry and basic artifact inspection to determine whether unauthorized cryptocurrency mining activity was present.

### At-a-Glance Summary

| Area | Details |
|------|---------|
| **Environment Type** | Windows endpoint (host-focused investigation) |
| **Affected Assets** | Workstation where suspicious executable launched from a user-writable location |
| **Primary Platforms / Services** | Windows endpoint logging subsystem; Splunk SIEM platform |
| **Telemetry Sources Reviewed** | Windows Security Event Logs (Event ID 4688 — Process Creation); host identity + user context fields; file path / naming artifacts |
| **Evidence Types** | Process execution patterns and command-line context; user/process lineage; suspicious binary location consistent with dropper/miner behavior |
| **Tools Used** | Splunk (SPL queries for filtering + pivoting); local file system inspection for validation; basic malware heuristics for triage decisions |
| **Investigation Focus** | Validate suspicious execution as cryptominer-like activity using process telemetry and host artifact confirmation |

### Operating Systems

- **Affected System (Victim Environment):**  
  Windows workstation where the suspicious executable was launched from a user-writable directory.

- **Analyst Environment:**  
  Windows-based analyst workstation used to query centralized logs and validate host artifacts.

### Platforms and Services

- **Windows Endpoint Logging Subsystem**  
  Generated native process creation telemetry used to identify executable names, file paths, and parent-child process relationships.

- **Splunk SIEM Platform**  
  Used to aggregate and search Windows Security Event Logs and correlate execution activity to specific hosts and users.

### Data Sources Reviewed

- **Windows Security Event Logs (Event ID 4688 — Process Creation)**  
  Reviewed to identify:
  - Execution of suspicious binaries
  - File paths indicating execution from temporary directories
  - Associated user accounts and hostnames

- **Host Identity and User Context Fields**  
  Used to attribute execution to a specific endpoint and logged-in user.

- **File Path and Naming Artifacts**  
  Reviewed to assess whether executable names and locations aligned with known cryptocurrency mining behavior.

### Tools and Analysis Techniques

- **Splunk (SPL Queries)**  
  Used to:
  - Filter for Event ID 4688 process creation events
  - Identify rare or suspicious executable names
  - Pivot on host and user fields to scope potential spread

- **File System Inspection (Local Validation)**  
  Used to confirm:
  - Executable placement in user-writable directories
  - Absence of legitimate application installation paths

- **Basic Malware Heuristics**  
  Used to evaluate miner-like behavior based on:
  - Executable naming conventions
  - Execution location
  - Potential for sustained CPU usage

This investigation demonstrates rapid endpoint triage workflows used by SOC analysts to validate suspicious execution alerts before escalating to full malware response procedures.


---

## Repository Structure & Supporting Documents

All investigation outputs are separated into focused reports to reflect common incident documentation practices.

### `investigation-walkthrough.md`

Provides a structured alert validation workflow showing how a SIEM detection was correlated with endpoint telemetry to determine whether the activity represented benign behavior or malicious resource abuse.

The walkthrough documents:

- Review of alert metadata and triggering conditions  
- Pivoting from alert context to raw Windows process creation logs  
- Attribution of execution to a specific user and endpoint  
- Evaluation of executable naming and execution path legitimacy  
- Validation of detection rule behavior and classification decision  

The walkthrough emphasizes evidence-based alert triage and classification rather than reliance on alert labels alone.


### `images`

Contains all screenshots referenced throughout the investigation, including:

- Original SIEM alert views
- Correlated Windows event logs
- Detection rule configuration evidence

These images visually support each analytical step and conclusion documented in the reports.


### `case-report.md`

Provides a structured incident case record including:

- Alert context
- Scope definition
- Evidence reviewed
- Final classification decision

Written in a format consistent with internal security case documentation.


### `detection-artifact-report.md`

Documents technical indicators and behaviors such as:

- Executable naming patterns
- Execution path characteristics
- Relevant Windows event fields

These artifacts can be translated into SIEM detection logic or threat hunting queries.


### `incident-response-report.md`

Details recommended response actions, including:

- Endpoint containment considerations
- Credential hygiene steps
- Validation and cleanup guidance

This report focuses on operational handling following confirmation of malicious activity.


### `incident-summary.md`

Provides a concise overview intended for non-technical stakeholders, covering:

- What occurred
- Why it matters
- Recommended next actions

This format supports communication with management, compliance, and IT leadership.


### `detection-and-hardening-recommendations.md`

Focuses on endpoint monitoring and execution control improvements related to unauthorized process activity and resource abuse.

Includes recommendations covering:

- Application allowlisting and execution restrictions  
- Detection tuning for cryptocurrency mining indicators  
- Monitoring of user-writable directory execution  
- Resource utilization anomaly detection  
- Host-based isolation workflows following confirmed abuse  

This file reflects how security teams document hardening and alerting improvements following validated SIEM detections.


### `MITRE-ATT&CK-mapping.md`

Maps observed behaviors to MITRE ATT\&CK techniques, including:

- User execution of suspicious binaries
- Resource hijacking through unauthorized mining activity

Includes both narrative explanations and a table-based mapping format for reporting and analysis.

---

## Intended Use

This investigation demonstrates structured alert analysis, log correlation, and evidence-based classification using endpoint telemetry and SIEM detections. It is designed to reflect how suspicious execution events are validated, documented, and translated into detection and response improvements.

---

## Relevance to Security Operations

Unauthorized process execution remains a common initial indicator of compromise or misuse.

This investigation demonstrates how centralized logging enables analysts to:

- Validate detections using endpoint telemetry
- Attribute activity to specific users and systems
- Identify execution behaviors that warrant containment

Even single-event alerts benefit from systematic investigation to avoid misclassification and to support appropriate response actions.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation is intended to demonstrate practical alert analysis, log correlation methodology, and professional incident documentation aligned with real operational workflows.
