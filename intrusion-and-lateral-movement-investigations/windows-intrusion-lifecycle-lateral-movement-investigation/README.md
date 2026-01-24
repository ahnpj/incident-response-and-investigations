# Windows Malware Intrusion Lifecycle Investigation (Lateral Movement and Multi-Stage Host Compromise)

**Category:** Intrusion and Lateral Movement  
**Primary Attack Surface:** Remote authentication services and internal network paths  
**Tactics Observed:** Reconnaissance, Credential Access, Lateral Movement, Persistence, Command and Control  
**Primary Data Sources:** Firewall Logs, Windows Authentication Logs, Sysmon Network Connection Events, OpenSSH Operational Logs

---

### Overview

This investigation analyzes a complete intrusion lifecycle on a Windows host, beginning with external reconnaissance and progressing through brute-force authentication, account manipulation, malware deployment, persistence, and post-compromise cleanup.

The analysis focuses on reconstructing attacker behavior using correlated firewall logs, authentication telemetry, endpoint execution events, file artifacts, and registry modifications to produce a complete timeline of compromise across multiple attack stages.

The investigation demonstrates how an analyst:
- Identifies reconnaissance through abnormal network scanning behavior
- Confirms initial access via exposed remote services
- Reconstructs brute-force authentication activity
- Detects attacker-created accounts and privilege escalation
- Identifies malware deployment and persistence mechanisms
- Detects cleanup actions intended to reduce attacker visibility

---

### What This Investigation Covers

This case analyzes post-compromise telemetry from a Windows endpoint that exhibited abnormal firewall, authentication, and execution activity.

The investigation identifies external network scanning, confirms exposed SSH as the access vector, reconstructs brute-force authentication attempts using OpenSSH logs, validates successful login to the Administrator account, detects attacker-created local accounts, confirms addition of those accounts to the Administrators group, identifies deletion of a legitimate user account, detects malware extraction and execution, and confirms registry-based persistence mechanisms.

Rather than relying on a single alert or telemetry source, the walkthrough emphasizes correlation across network, authentication, and host telemetry to reconstruct attacker tradecraft across the full intrusion lifecycle.

---

### How to Navigate This Investigation

This case is documented across multiple focused reports to reflect how multi-stage intrusions are handled in real SOC and incident response workflows. Supporting reports provide incident summaries, response actions, detection artifacts, and security improvement recommendations. A breakdown of each file is provided below.

If you want to follow the investigation step by step, start with:

**`investigation-walkthrough.md`**

---

### Repository Structure & Supporting Documents

All investigation outputs are separated into focused reports aligned with common incident documentation practices for multi-stage intrusions.

| File / Folder | Purpose | Contents and Focus |
|-------------|--------|--------------------|
| `investigation-walkthrough.md` | Full intrusion reconstruction narrative spanning reconnaissance, access, persistence, and cleanup stages. | Documents identification of network reconnaissance through firewall telemetry, detection of exposed services and brute-force authentication attempts, validation of successful remote access via SSH logs, detection of attacker-created administrative accounts, identification of malware extraction and staging activity, confirmation of registry-based persistence mechanisms, and detection of cleanup actions through account deletion. Emphasizes timeline-based correlation across network, authentication, and host telemetry. |
| `images/` | Visual evidence supporting each stage of intrusion reconstruction. | Contains screenshots showing firewall reconnaissance, SSH authentication failures and successes, account creation and deletion events, malware staging activity, and registry persistence confirmation. |
| `case-report.md` | Comprehensive technical case record documenting the full attack timeline. | Summarizes initial access vector, privilege escalation, malware deployment, persistence mechanisms, cleanup actions, and final incident determination for escalation and review. |
| `detection-artifact-report.md` | Detection opportunities across all phases of the intrusion. | Documents network reconnaissance indicators, authentication abuse patterns, malware staging artifacts, and persistence behaviors suitable for layered detection strategies across perimeter, identity, and endpoint telemetry. |
| `incident-response-report.md` | Coordinated remediation actions across network, identity, and endpoint controls. | Covers account remediation, service hardening, persistence removal, and post-incident monitoring recommendations reflecting enterprise-scale response planning. |
| `incident-summary.md` | Executive-level overview of intrusion scope and operational impact. | Summarizes business exposure, systems affected, and remediation priorities for leadership, compliance, and infrastructure stakeholders. |
| `detection-and-hardening-recommendations.md` | Systemic control improvements identified through lifecycle analysis. | Includes recommendations for external service exposure reduction, authentication hardening, endpoint protection improvements, centralized logging enhancements, and post-compromise detection for cleanup activity and attacker dwell time. |
| `MITRE-ATT&CK-mapping.md` | Mapping of each intrusion phase to ATT&CK techniques. | Maps reconnaissance, access, persistence, and cleanup behaviors to ATT&CK tactics and techniques using evidence from network, authentication, and host telemetry. |

---

### Environment, Data Sources, and Tools

This investigation reconstructs a full intrusion lifecycle on a Windows host using correlated perimeter, authentication, and endpoint telemetry to analyze reconnaissance, initial access, post-exploitation activity, persistence, and cleanup behaviors.

### Environment and Investigation Scope (At a Glance)

| Area | Details |
|------|---------|
| **Environment Type** | Multi-host Windows network (intrusion progression case) |
| **Affected Assets** | Windows endpoints accessed remotely; perimeter device telemetry; remote access service telemetry |
| **Victim Operating System** | Windows endpoint exposed to external network access and compromised through credential-based remote access |
| **Analyst Operating System** | Windows-based analyst workstation used to query SIEM telemetry, decode artifacts, and perform enrichment |
| **Primary Platforms / Services** | FortiGate firewall (perimeter), OpenSSH service on Windows, Windows local authentication and account management services, Splunk SIEM platform |
| **Investigation Focus** | Track intrusion from reconnaissance through lateral movement using perimeter and host telemetry with evidence-backed pivots |

### Data Sources, Evidence, and Analysis Techniques

| Area | Details |
|------|---------|
| **Primary Telemetry Sources** | FortiGate firewall logs, OpenSSH operational logs, Windows Security Event Logs, Sysmon operational logs, and file system artifacts |
| **Network Reconnaissance Evidence** | Firewall telemetry showing scanning behavior and repeated inbound connection attempts to exposed services |
| **Authentication Evidence** | OpenSSH logs confirming brute-force attempts and successful credential-based access |
| **Account Manipulation Evidence** | Windows Security logs showing local account creation, administrator group membership changes, and account deletion |
| **Malware Execution Evidence** | Sysmon events and file artifacts confirming malware extraction, staging, and execution |
| **Persistence Evidence** | Registry modification events tied to startup execution mechanisms |
| **Splunk Correlation Techniques** | Pivoting across firewall, SSH, and endpoint logs to correlate authentication, execution, and persistence events into a unified timeline |
| **CyberChef Usage** | Decoding encoded command-line parameters and normalizing artifact values extracted from logs |
| **PowerShell Validation** | Enumeration of persistence locations, suspicious files, and account configuration changes |
| **Threat Intelligence Enrichment** | Validation of malware hashes and identification of tooling associated with observed artifacts |
| **Operational Workflow Context** | Demonstrates multi-source correlation techniques used when reconstructing full attack lifecycles from stored telemetry |

This investigation demonstrates how attackers leave small artifacts across many systems rather than a single obvious indicator, requiring correlation across multiple telemetry domains.

---

### Intended Use

This investigation demonstrates full intrusion reconstruction using layered telemetry rather than isolated alerts. It reflects how analysts validate attacker behavior across multiple stages of compromise and translate findings into containment and hardening actions.

---

### Relevance to Security Operations

Multi-stage intrusions often distribute evidence across network, identity, and endpoint systems.

This investigation demonstrates how defenders can correlate reconnaissance to exploitation, reconstruct authentication abuse, identify persistence mechanisms, and detect cleanup behavior designed to reduce visibility. Comprehensive correlation enables confident incident classification and effective containment.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation demonstrates full lifecycle reconstruction, cross-source correlation, and professional incident documentation aligned with operational response workflows.
