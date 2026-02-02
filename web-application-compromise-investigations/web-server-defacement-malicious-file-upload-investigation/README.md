# Web Server Defacement Investigation (Malicious File Upload Exploitation and Web Shell Deployment)

**Category:** Web Application Compromise  
**Primary Attack Surface:** Web application file upload functionality  
**Tactics Observed:** Initial Access, Persistence, Command and Control, Impact  
**Primary Data Sources:** HTTP Traffic Logs, IDS Alerts (Suricata), Firewall UTM Logs, Host Process Telemetry, File System Artifacts

---

### Overview

This investigation analyzes a multi-stage web server compromise that resulted in public defacement of a Joomla-based website. The attack chain includes reconnaissance, vulnerability scanning, credential brute force, malware upload, command-and-control communication, and modification of hosted content.

The analysis focuses on correlating web, IDS, firewall, and host telemetry in Splunk to reconstruct attacker behavior across the full intrusion lifecycle.

The investigation demonstrates how an analyst:
- Detects reconnaissance and vulnerability scanning
- Identifies credential brute-force attacks against web admin portals
- Confirms payload upload and execution
- Detects outbound command-and-control communication
- Identifies actions taken to modify hosted content

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

This case analyzes telemetry associated with a compromised web server hosting a Joomla application.

The investigation identifies automated vulnerability scanning using IDS signatures and HTTP metadata, attributes scanning to Acunetix tooling via User-Agent analysis, detects repeated POST requests to Joomla admin login pages, identifies successful authentication after brute-force attempts, confirms executable upload to the web server, detects malware execution via Sysmon process telemetry, identifies outbound communication to attacker infrastructure, and confirms retrieval of external content used in defacement.

The walkthrough emphasizes log correlation across multiple data sources to build a complete attack narrative.

---

### How to Navigate This Investigation

This case is documented across multiple focused reports to reflect how web compromise incidents are handled in real SOC and incident response workflows. Supporting reports provide incident summaries, response actions, detection artifacts, and security improvement recommendations. A breakdown of each file is provided below.

If you want to follow the investigation step by step, start with:

**`investigation-walkthrough.md`**

---

### Repository Structure & Supporting Documents

All investigation outputs are separated into focused reports aligned with common incident documentation practices.

| File / Folder | Purpose | Contents and Focus |
|-------------|--------|--------------------|
| `investigation-walkthrough.md` | Multi-source log correlation walkthrough reconstructing the full attack chain leading to public website defacement. | Documents identification of reconnaissance and vulnerability scanning behavior, attribution of scanning to known tooling using User-Agent analysis, detection of brute-force authentication against web administration portals, confirmation of malware upload via HTTP POST activity, correlation of file upload with host-based execution telemetry, identification of outbound command-and-control communication, and validation of content modification and public-facing defacement. Demonstrates how web, IDS, firewall, and host telemetry can be correlated to reconstruct attacker behavior across multiple stages. |
| `images/` | Visual evidence supporting each investigative step and analytical pivot. | Contains screenshots and log excerpts showing reconnaissance and scanning activity, Joomla admin brute-force attempts, file upload and execution events, outbound C2 traffic, defacement confirmation, and supporting views used to validate the timeline and conclusions derived from each data source. |
| `case-report.md` | Technical narrative of the full attack chain from reconnaissance through impact. | Summarizes attack stages, evidence sources, impact validation, and final incident determination in a format consistent with SOC case documentation and post-incident review. |
| `detection-artifact-report.md` | Detection-relevant indicators derived from web, IDS, firewall, and host telemetry. | Documents indicators related to vulnerability scanning, web brute-force attempts, malicious upload behavior, suspicious host execution, and related network destinations to support WAF, SIEM, and host-based detection development. |
| `incident-response-report.md` | Operational response actions required to contain and recover from public-facing compromise. | Covers remediation actions including malware removal, credential resets, web application patching, validation of persistence removal, and content restoration steps aligned with recovery from website defacement incidents. |
| `incident-summary.md` | Executive-level overview of public website defacement and service disruption. | Summarizes reputational impact, system exposure, and recovery requirements for management, communications teams, and compliance stakeholders without requiring technical investigation detail. |
| `detection-and-hardening-recommendations.md` | Preventive controls and monitoring improvements to reduce exposure to web exploitation and unauthorized content modification. | Includes recommendations for file upload validation and execution prevention controls, WAF configuration and tuning, least-privilege permissions for web service accounts, outbound network restrictions for server systems, and file integrity monitoring for web root directories based on gaps and opportunities identified during the investigation. |
| `MITRE-ATT&CK-mapping.md` | Mapping of web exploitation, execution, command-and-control, and impact behaviors to MITRE ATT&CK techniques. | Maps attacker behaviors using evidence from web, IDS, firewall, and host logs, presented in both narrative and table formats to support standardized classification, reporting, and detection validation. |

---

### Environment, Data Sources, and Tools

This investigation reconstructs a full web server compromise resulting in public website defacement using correlated network, application, IDS, and host telemetry associated with a Joomla content management system.

#### Environment and Investigation Scope (At a Glance)

| Area | Details |
|------|---------|
| **Environment Type** | Linux-based web server (CMS exploitation and impact) |
| **Affected Assets** | Joomla CMS, web server application stack, uploaded files and web content, host process activity tied to exploitation |
| **Victim Operating System** | Linux-based web server hosting the Joomla content management system and processing inbound and outbound HTTP traffic |
| **Analyst Operating System** | Windows-based analyst workstation used to query SIEM telemetry, analyze HTTP payloads, and perform threat intelligence enrichment |
| **Primary Platforms / Services** | Joomla CMS, web server application stack, Suricata IDS, FortiGate firewall/UTM, Splunk SIEM platform |
| **Investigation Focus** | Confirm file-upload exploitation leading to defacement, establish timeline, and validate indicators across network and host telemetry |

#### Data Sources, Evidence, and Analysis Techniques

| Area | Details |
|------|---------|
| **Primary Telemetry Sources** | HTTP traffic logs (`stream:http` via Splunk), Suricata IDS alerts (`suricata` via Splunk), FortiGate UTM logs (`fortigate_utm` via Splunk), host process telemetry (Sysmon via Splunk), and file/hash artifacts |
| **Web Request Evidence** | Malicious upload requests, repeated POSTs to Joomla admin login pages, authentication success following brute-force attempts, and outbound requests used to retrieve externally hosted defacement content |
| **IDS Confirmation Evidence** | Scanner and exploit signatures (including automated tooling detection such as Acunetix) and malicious request patterns used to corroborate reconnaissance and exploitation attempts |
| **Firewall/UTM Corroboration** | Inbound and outbound connections used to validate attacker infrastructure communication and retrieval of external resources associated with defacement |
| **Host Execution Evidence** | Sysmon process telemetry confirming execution of uploaded payloads and outbound connections initiated by processes associated with exploitation and post-compromise activity |
| **File and Hash Artifacts** | Dropped executable names, timestamps aligned with execution, and hash indicators used for validation and enrichment |
| **Splunk Correlation Techniques** | Pivots across HTTP, IDS, firewall, and Sysmon sources, extraction of request parameters and file names from HTTP payloads, and correlation of activity across multiple stages of compromise |
| **CyberChef Usage** | Decoding URL-encoded payloads and extracting file names and parameters from HTTP request bodies to support artifact validation |
| **Threat Intelligence Enrichment** | Validation of domains, IPs, and file hashes using OSINT sources such as VirusTotal, ThreatMiner, and Hybrid Analysis to confirm maliciousness and infrastructure context |
| **Manual Timeline Reconstruction** | Alignment of reconnaissance, authentication success, upload activity, host execution, outbound communication, and defacement delivery into a coherent intrusion timeline |
| **Operational Workflow Context** | Demonstrates multi-layer correlation commonly used in SOC environments when reconstructing web compromise and public defacement incidents from mixed network and host telemetry |

This investigation demonstrates multi-layer correlation techniques commonly used in SOC environments when analyzing web server compromise and public website defacement incidents.

---

### Intended Use

This investigation demonstrates how defenders can reconstruct complex web attacks using correlated telemetry rather than relying on single alerts.

---

### Relevance to Security Operations

Web server compromises frequently involve multiple small signals across different systems.

This investigation demonstrates how defenders can identify early scanning behavior, confirm credential abuse, detect malicious upload and execution activity, and recognize impact actions associated with unauthorized content modification. Correlating these stages enables faster containment and supports development of stronger detections and hardening controls.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation demonstrates multi-source log correlation, web attack analysis, and professional incident documentation aligned with security operations workflows.


