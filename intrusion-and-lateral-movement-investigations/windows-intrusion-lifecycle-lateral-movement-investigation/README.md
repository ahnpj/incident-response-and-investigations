# Windows Malware Intrusion Lifecycle Investigation (Lateral Movement and Multi-Stage Host Compromise on Windows)

**Category:** Intrusion and Lateral Movement  
**Primary Attack Surface:** Remote authentication services and internal network paths  
**Tactics Observed:** Reconnaissance, Credential Access, Lateral Movement, Command and Control  
**Primary Data Sources:** Firewall Logs, Windows Authentication Logs, Sysmon Network Connection Events, OpenSSH Operational Logs

This investigation analyzes a complete intrusion lifecycle on a Windows host, beginning with external reconnaissance and progressing through brute-force authentication, account manipulation, malware deployment, persistence, and post-compromise cleanup.

The analysis focuses on reconstructing attacker behavior using correlated firewall logs, authentication telemetry, endpoint events, file artifacts, and registry modifications to produce a complete timeline of compromise.

The investigation demonstrates how an analyst:

- Identifies reconnaissance through network scanning behavior
- Confirms initial access via exposed remote services
- Reconstructs brute-force authentication activity
- Detects attacker-created accounts and privilege escalation
- Identifies malware deployment and persistence mechanisms
- Detects account cleanup actions intended to reduce visibility

---

## What This Investigation Covers

This case analyzes post-compromise telemetry from a Windows endpoint that exhibited abnormal firewall and authentication activity.

The investigation walks through how the analyst:

- Identifies network service scanning from external infrastructure
- Confirms exposed SSH service as the access vector
- Reconstructs brute-force authentication using OpenSSH logs
- Confirms successful login to the Administrator account
- Detects attacker-created local account (`sysadmin`)
- Confirms addition of the account to the Administrators group
- Detects deletion of a legitimate user account
- Identifies malware extraction and execution
- Confirms registry-based persistence

The walkthrough emphasizes **correlation across network, authentication, and host telemetry** to reconstruct attacker tradecraft.

---

## Environment, Data Sources, and Tools

This investigation reconstructs a full intrusion lifecycle on a Windows host using correlated perimeter, authentication, and endpoint telemetry to analyze reconnaissance, initial access, post-exploitation activity, persistence, and cleanup behaviors.

### At-a-Glance Summary

| Area | Details |
|------|---------|
| **Environment Type** | Multi-host Windows network (intrusion progression case) |
| **Affected Assets** | Windows endpoints accessed remotely; perimeter device telemetry; remote access service telemetry |
| **Primary Platforms / Services** | FortiGate firewall (perimeter); OpenSSH service on Windows; Windows local authentication/account management; Splunk SIEM platform |
| **Telemetry Sources Reviewed** | FortiGate firewall logs (via Splunk); OpenSSH Operational logs (via Splunk); Windows Security Event Logs (via Splunk); Sysmon Operational logs (via Splunk); file system artifacts |
| **Evidence Types** | Recon / inbound access patterns; credential-based remote access events; cross-host correlation for lateral movement; file artifacts supporting intrusion phases |
| **Tools Used** | Splunk (SPL correlation + host pivots); CyberChef (artifact decoding/normalization); PowerShell (supporting validation steps documented); OSINT/threat intel sources for enrichment |
| **Investigation Focus** | Track intrusion from initial access through lateral movement using perimeter + host telemetry and evidence-backed pivots |

### Operating Systems

- **Affected System (Victim Environment):**  
  Windows endpoint exposed to external network access and compromised through credential-based remote access.

- **Analyst Environment:**  
  Windows-based analyst workstation used to query SIEM telemetry, decode artifacts, and perform threat intelligence enrichment.

### Platforms and Services

- **FortiGate Firewall (Perimeter Device)**  
  Generated network telemetry used to identify external scanning and inbound connection attempts targeting exposed services.

- **OpenSSH Service on Windows**  
  Provided remote authentication access exploited during brute-force attacks and initial compromise.

- **Windows Local Authentication and Account Management Services**  
  Generated security events associated with attacker-created accounts, administrator group changes, and account deletion during cleanup.

- **Splunk SIEM Platform**  
  Used to correlate firewall, SSH, Windows Security, and Sysmon telemetry into a unified investigation timeline.

### Data Sources Reviewed

- **FortiGate Firewall Logs (via Splunk)**  
  Reviewed to identify:
  - External scanning activity
  - Repeated connection attempts to exposed SSH services

- **OpenSSH Operational Logs (via Splunk)**  
  Reviewed to confirm:
  - Brute-force authentication attempts
  - Successful SSH logins from external IP addresses

- **Windows Security Event Logs (via Splunk)**  
  Reviewed to validate:
  - Local account creation
  - Administrator group membership changes
  - Account deletion during attacker cleanup

- **Sysmon Operational Logs (via Splunk)**  
  Reviewed to identify:
  - Malware extraction and execution
  - File creation in user and system directories
  - Registry modifications used for persistence

- **File System Artifacts**  
  Examined to validate:
  - Dropped malware files
  - Masquerading executables and renamed binaries

### Tools and Analysis Techniques

- **Splunk (SPL Queries)**  
  Used to:
  - Pivot across firewall, SSH, and endpoint logs
  - Correlate authentication, execution, and persistence events
  - Reconstruct attacker movement across multiple stages

- **CyberChef**  
  Used to:
  - Decode encoded command-line parameters
  - Normalize artifact values extracted from logs

- **PowerShell**  
  Used to:
  - Validate persistence locations
  - Enumerate suspicious files and accounts
  - Confirm system configuration changes

- **OSINT and Threat Intelligence Sources**  
  Used to:
  - Validate malware hashes
  - Identify known malicious tooling associated with observed artifacts

This investigation demonstrates multi-source correlation techniques commonly used by SOC analysts and incident responders when reconstructing full attack lifecycles from stored telemetry.

---

## Repository Structure & Supporting Documents

### `investigation-walkthrough.md`

Provides a comprehensive intrusion reconstruction walkthrough spanning reconnaissance, initial access, privilege escalation, malware deployment, persistence, and cleanup actions.

The walkthrough documents:

- Identification of network reconnaissance through firewall telemetry  
- Detection of exposed services and brute-force authentication attempts  
- Validation of successful remote access via SSH logs  
- Detection of attacker-created administrative accounts  
- Identification of malware extraction and staging activity  
- Confirmation of registry-based persistence mechanisms  
- Detection of attacker cleanup actions through account deletion  

The walkthrough emphasizes timeline-based correlation across network, authentication, and host telemetry to reconstruct attacker decision-making throughout the intrusion lifecycle.


### `images`

Screenshots showing:

- Firewall reconnaissance evidence
- SSH authentication failures and success
- Account creation and deletion events
- Malware staging and registry persistence

Supports full lifecycle reconstruction.


### `case-report.md`

Provides comprehensive technical documentation of the full attack timeline.

Summarizes:

- Initial access vector  
- Privilege escalation  
- Malware deployment  
- Cleanup actions  
- Final incident determination


### `detection-artifact-report.md`

Documents detection opportunities across all attack phases, including:

- Network reconnaissance  
- Authentication abuse  
- Malware staging  
- Persistence mechanisms  

Supports layered detection strategies across multiple telemetry sources.


### `incident-response-report.md`

Focuses on coordinated remediation actions across network, identity, and endpoint controls.

Includes:

- Account remediation  
- Service hardening  
- Persistence removal  
- Post-incident monitoring recommendations  

Reflects enterprise-scale response planning following multi-stage intrusions.


### `incident-summary.md`

Provides a high-level overview of the complete intrusion and operational impact.

Intended for:

- Executive leadership  
- Compliance teams  
- Infrastructure management  

Summarizes scope of compromise, business exposure, and remediation priorities.


### `detection-and-hardening-recommendations.md`

Focuses on systemic control improvements across network, identity, and endpoint layers to reduce the likelihood and impact of multi-stage intrusions.

Includes recommendations covering:

- External service exposure reduction and firewall controls  
- Authentication hardening and account protection strategies  
- Endpoint protection and persistence prevention controls  
- Centralized logging and cross-domain correlation improvements  
- Post-compromise detection for cleanup and attacker dwell time  

This file reflects how security teams document architectural and configuration improvements following full intrusion lifecycle incidents.


### `MITRE-ATT&CK-mapping.md`

Maps each stage of the intrusion lifecycle to MITRE ATT&CK techniques using network, authentication, and host telemetry.

Includes:

- Reconnaissance, access, persistence, and impact techniques  
- Evidence supporting each stage of the attack  

Supports full lifecycle threat modeling and detection validation.

---

## Intended Use

This investigation demonstrates full intrusion reconstruction using layered telemetry rather than isolated alerts. It emphasizes understanding attacker decision-making across the entire compromise lifecycle.

---

## Relevance to Security Operations

Multi-stage intrusions often leave small artifacts across many systems rather than a single obvious indicator.

This investigation demonstrates how defenders can:

- Correlate reconnaissance to exploitation
- Reconstruct authentication abuse
- Identify persistence and cleanup behavior

Comprehensive correlation enables confident incident classification and effective containment.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation demonstrates full lifecycle reconstruction, cross-source correlation, and structured incident documentation aligned with operational response workflows.