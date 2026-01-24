# Web Server Defacement Investigation (Malicious File Upload Exploitation and Web Shell Deployment)

**Category:** Web Application Compromise  
**Primary Attack Surface:** Web application file upload functionality  
**Tactics Observed:** Initial Access, Persistence, Command and Control, Impact  
**Primary Data Sources:** HTTP Traffic Logs, IDS Alerts (Suricata), Firewall UTM Logs, Host Process Telemetry, File System Artifacts

This investigation analyzes a multi-stage web server compromise that resulted in public defacement of a Joomla-based website. The attack chain includes reconnaissance, vulnerability scanning, credential brute force, malware upload, command-and-control communication, and modification of hosted content.

The analysis focuses on correlating web, IDS, firewall, and host telemetry in Splunk to reconstruct attacker behavior across the full intrusion lifecycle.

The investigation demonstrates how an analyst:

- Detects reconnaissance and vulnerability scanning
- Identifies credential brute-force attacks against web admin portals
- Confirms payload upload and execution
- Detects outbound command-and-control communication
- Identifies actions taken to modify hosted content

---

## What This Investigation Covers

This case analyzes telemetry associated with a compromised web server hosting a Joomla application.

The investigation walks through how the analyst:

- Identifies automated vulnerability scanning using IDS signatures and HTTP metadata
- Attributes scanning to Acunetix tooling via User-Agent analysis
- Detects repeated POST requests to Joomla admin login pages
- Identifies successful authentication after brute-force attempts
- Confirms executable upload to the web server
- Detects malware execution via Sysmon process telemetry
- Identifies outbound communication to attacker infrastructure
- Confirms retrieval of external content used in defacement

The walkthrough emphasizes **log correlation across multiple data sources** to build a complete attack narrative.

---

## Environment, Data Sources, and Tools

This investigation reconstructs a full web server compromise resulting in public website defacement using correlated network, application, IDS, and host telemetry associated with a Joomla content management system.

### At-a-Glance Summary

| Area | Details |
|------|---------|
| **Environment Type** | Linux-based web server (CMS exploitation + impact) |
| **Affected Assets** | Joomla CMS; web server application stack; uploaded files/web content; host process activity tied to exploitation |
| **Primary Platforms / Services** | Joomla CMS; web server application stack; Suricata IDS; FortiGate firewall/UTM; Splunk SIEM platform |
| **Telemetry Sources Reviewed** | HTTP traffic logs (`stream:http` via Splunk); Suricata IDS alerts (`suricata` via Splunk); FortiGate UTM logs (`fortigate_utm` via Splunk); host process telemetry (Sysmon via Splunk); file + hash artifacts |
| **Evidence Types** | Malicious upload requests and follow-on activity; IDS confirmations; firewall/UTM corroboration; suspicious process execution tied to defacement; recovered file/hash indicators |
| **Tools Used** | Splunk (SPL correlation across web/IDS/firewall/host); CyberChef (decode/transform artifacts); OSINT/threat intel (VirusTotal, ThreatMiner, Hybrid Analysis); manual timeline reconstruction |
| **Investigation Focus** | Confirm file-upload exploitation leading to defacement, establish timeline, and validate indicators across network + host telemetry |

### Operating Systems

- **Affected System (Victim Environment):**  
  Linux-based web server hosting the Joomla content management system and processing inbound and outbound HTTP traffic.

- **Analyst Environment:**  
  Windows-based analyst workstation used to query SIEM telemetry, analyze HTTP payloads, and perform threat intelligence enrichment.

### Platforms and Services

- **Joomla Content Management System (CMS)**  
  Provided the administrative interface targeted for credential brute force and file upload, enabling attackers to deploy malware and modify site content.

- **Web Server Application Stack**  
  Processed inbound HTTP requests, file uploads, and outbound requests for externally hosted defacement content.

- **Intrusion Detection System (Suricata)**  
  Generated exploit and vulnerability scanning alerts, including detection of automated scanners and known exploit attempts.

- **FortiGate Firewall / UTM**  
  Recorded inbound and outbound network connections used to validate command-and-control and external resource retrieval.

- **Splunk SIEM Platform**  
  Used to correlate HTTP traffic, IDS alerts, firewall logs, and host telemetry into a unified investigation timeline.

### Data Sources Reviewed

- **HTTP Traffic Logs (`stream:http` via Splunk)**  
  Reviewed to identify:
  - Automated vulnerability scanning behavior
  - Login attempts and authentication success
  - File upload requests
  - Outbound requests for defacement content

- **Suricata IDS Alerts (`suricata` via Splunk)**  
  Reviewed to identify:
  - Exploit probes (e.g., Shellshock)
  - Scanner signatures (e.g., Acunetix)
  - Malicious request patterns

- **Firewall and Web Filtering Logs (`fortigate_utm` via Splunk)**  
  Reviewed to validate:
  - Outbound connections to attacker infrastructure
  - External hosting of defacement images

- **Host Process Telemetry (Sysmon via Splunk)**  
  Reviewed to confirm:
  - Execution of uploaded malware payloads
  - Outbound network connections initiated by malicious processes

- **File and Hash Artifacts**  
  Reviewed to validate:
  - Dropped executable names
  - Timestamps aligned with malware execution

### Tools and Analysis Techniques

- **Splunk (SPL Queries)**  
  Used to:
  - Pivot across HTTP, IDS, firewall, and Sysmon data sources
  - Extract request parameters and file names from HTTP payloads
  - Correlate attacker activity across multiple stages of compromise

- **CyberChef**  
  Used to:
  - Decode URL-encoded payloads
  - Extract file names and parameters from HTTP request bodies

- **OSINT and Threat Intelligence Sources (VirusTotal, ThreatMiner, Hybrid Analysis)**  
  Used to:
  - Validate malicious domains and IP addresses
  - Identify malware associated with uploaded executables
  - Confirm scanner and exploit infrastructure

- **Manual Timeline Reconstruction**  
  Used to align:
  - Reconnaissance activity
  - Authentication success
  - Malware execution
  - Defacement delivery

This investigation demonstrates multi-layer correlation techniques commonly used in SOC environments when analyzing web server compromise and public website defacement incidents.

---

## Repository Structure & Supporting Documents

### `investigation-walkthrough.md`

Provides a multi-source log correlation walkthrough reconstructing the full attack chain leading to public website defacement.

The walkthrough documents:

- Identification of reconnaissance and vulnerability scanning behavior  
- Attribution of scanning to known tooling using User-Agent analysis  
- Detection of brute-force authentication against web administration portals  
- Confirmation of malware upload via HTTP POST activity  
- Correlation of file upload with host-based execution telemetry  
- Identification of outbound command-and-control communication  
- Validation of content modification and public-facing defacement  

The walkthrough demonstrates how correlating web, IDS, firewall, and endpoint telemetry enables full reconstruction of complex web attacks.


### `images`

Screenshots showing:

- Reconnaissance and scanning activity
- Joomla admin brute-force attempts
- File upload and execution events
- Outbound C2 traffic
- Defacement confirmation
- Scanning detection  
- Login abuse  
- Malware execution  

Supports reconstruction of attacker activity.


### `case-report.md`

Provides the technical narrative of the full attack chain from reconnaissance to defacement.

Summarizes:

- Attack stages  
- Evidence sources  
- Impact validation  
- Final incident determination


### `detection-artifact-report.md`

Documents indicators related to:

- Vulnerability scanning  
- Web brute-force attempts  
- Malware upload and execution  

Supports development of WAF, SIEM, and host-based detections.


### `incident-response-report.md`

Focuses on remediation actions including:

- Malware removal  
- Credential resets  
- Web application patching  
- Content restoration  

Reflects operational recovery from public-facing server compromise.


### `incident-summary.md`

Provides an executive-level overview of public website defacement and service disruption.

Intended for:

- Management  
- Communications teams  
- Compliance stakeholders  

Summarizes reputational impact, system exposure, and recovery requirements.


### `detection-and-hardening-recommendations.md`

Focuses on server, application, and network controls to reduce exposure to web exploitation and prevent unauthorized content modification.

Includes recommendations covering:

- File upload validation and execution prevention controls  
- Web application firewall configuration and tuning  
- Least-privilege permissions for web service accounts  
- Outbound network restrictions for server systems  
- File integrity monitoring for web root directories  

This file reflects how security teams document hardening actions and monitoring improvements following web server compromise.


### `MITRE-ATT&CK-mapping.md`

Maps web exploitation, malware execution, and impact actions to MITRE ATT&CK techniques using multi-source telemetry.

Includes:

- Web exploitation and command execution techniques  
- Evidence from web, host, and network logs  

Supports structured classification of web server compromise activity.

---

## Intended Use

This investigation demonstrates how defenders can reconstruct complex web attacks using correlated telemetry rather than relying on single alerts.

---

## Relevance to Security Operations

Web server compromises frequently involve multiple small signals across different systems.

This investigation demonstrates how defenders can:

- Identify early scanning behavior
- Confirm credential abuse
- Detect malware execution
- Recognize impact actions

Correlating these stages enables faster containment and improved detection engineering.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation demonstrates multi-source log correlation, web attack analysis, and professional incident documentation aligned with security operations workflows.