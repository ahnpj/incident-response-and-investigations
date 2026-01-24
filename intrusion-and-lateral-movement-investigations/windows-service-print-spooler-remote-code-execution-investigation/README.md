# Windows Service Exploitation Investigation (Print Spooler Remote Code Execution)

**Category:** Intrusion and Lateral Movement  
**Primary Attack Surface:** Network-accessible Windows services  
**Tactics Observed:** Initial Access, Privilege Escalation, Execution, Lateral Movement  
**Primary Data Sources:** Windows Event Logs, Sysmon Process and Network Events, Network Packet Capture (PCAP)

This investigation analyzes abuse of a trusted Windows service that resulted in unauthorized file transfer, remote code execution, and establishment of a reverse shell connection. The attacker leveraged native Windows components to execute malicious code and communicate with external infrastructure without deploying custom executables

The analysis focuses on reconstructing attacker behavior using host-based telemetry and network traffic, with emphasis on how legitimate Windows services can be abused to deliver payloads, execute code, and establish command-and-control channels.


The investigation demonstrates how an analyst:

- Identifies service abuse through SMB and file system telemetry
- Distinguishes malicious driver files from legitimate Windows components
- Confirms execution of attacker-supplied code through trusted services
- Correlates host execution with network-level command-and-control activity

## What This Investigation Covers

This case simulates post-compromise log analysis following exploitation of the Windows Print Spooler service. The vulnerable condition and exploit execution occurred prior to analysis; the investigation focuses solely on reconstructing attacker behavior from collected telemetry.

The investigation walks through how the analyst:

- Identifies SMB access targeting the `spoolss` named pipe
- Confirms file transfer from attacker-controlled infrastructure
- Detects malicious DLL placement in Print Spooler driver directories
- Attributes execution to the Print Spooler service (`spoolsv.exe`)
- Identifies use of `rundll32.exe` to load attacker-controlled code
- Correlates execution with outbound network connections
- Confirms interactive reverse shell activity via packet capture
- Verifies SYSTEM-level execution context using post-exploitation commands

Rather than focusing on exploit mechanics, the walkthrough emphasizes **defender-visible artifacts** that remain after exploitation.

---

## Environment, Data Sources, and Tools

This investigation analyzes service-level exploitation of Windows Print Services resulting in remote code execution and interactive shell access using correlated host and network telemetry.

### At-a-Glance Summary

| Area | Details |
|------|---------|
| **Environment Type** | Windows Server (service exploitation investigation) |
| **Affected Assets** | Print Spooler service; SMB file services; exploit-triggered process/service activity |
| **Primary Platforms / Services** | Windows Print Spooler service; SMB file services; Splunk SIEM platform |
| **Telemetry Sources Reviewed** | Windows Security Event Logs (via Splunk); Sysmon Operational Logs (via Splunk); network packet capture (PCAP) |
| **Evidence Types** | Service/exploitation-linked process creation; authentication and service activity around exploitation window; packet-level confirmation of network behavior |
| **Tools Used** | Splunk (SPL correlation + scoping); Wireshark (PCAP validation); PowerShell (supporting validation steps as documented); manual timeline correlation across host + network artifacts |
| **Investigation Focus** | Validate Print Spooler exploitation leading to attacker-controlled code execution and post-exploitation activity |

### Operating Systems

- **Affected System (Victim Environment):**  
  Windows Server hosting the Print Spooler service that was abused to install malicious printer drivers and execute attacker-controlled code.

- **Analyst Environment:**  
  Windows-based analyst workstation used to query SIEM telemetry and analyze packet capture data.

### Platforms and Services

- **Windows Print Spooler Service**  
  Abused by the attacker to load malicious printer driver files that executed arbitrary code on the server.

- **SMB File Services**  
  Used by the attacker to transfer malicious DLL and driver files to the target system during exploitation.

- **Splunk SIEM Platform**  
  Used to correlate Windows Security logs, Sysmon telemetry, and network indicators to reconstruct the exploitation sequence.

### Data Sources Reviewed

- **Windows Security Event Logs (via Splunk)**  
  Reviewed to identify:
  - SMB file access activity
  - Service-related interactions during driver installation
  - Authentication context of exploitation attempts

- **Sysmon Operational Logs (via Splunk)**  
  Reviewed to identify:
  - File creation in printer driver directories
  - Malicious process execution chains
  - Outbound network connections following exploitation

- **Network Packet Capture (PCAP)**  
  Reviewed to validate:
  - Reverse shell connections
  - Interactive command execution
  - Attacker-controlled communication channels

### Tools and Analysis Techniques

- **Splunk (SPL Queries)**  
  Used to:
  - Pivot across Security and Sysmon logs
  - Correlate file creation and process execution events
  - Scope post-exploitation activity on the server

- **Wireshark**  
  Used to analyze packet captures and confirm:
  - Reverse shell establishment
  - Command-and-control traffic patterns

- **PowerShell**  
  Used to validate:
  - Presence of dropped files
  - Persistence or additional payload staging on the host

- **Manual Timeline Correlation**  
  Used to align:
  - SMB file transfer
  - Driver installation
  - Process execution
  - Network callbacks

This investigation demonstrates how service exploitation can be reconstructed using combined host and network telemetry, even when exploit delivery mechanics are not directly observable in logs.

---

## Repository Structure \& Supporting Documents

All investigation outputs are separated into focused reports aligned with common incident documentation practices.

### `investigation-walkthrough.md`

Provides a host and network correlation walkthrough focused on reconstructing exploitation of a trusted Windows service and subsequent post-exploitation activity.

The walkthrough documents:

- Detection of service-related SMB access patterns  
- Identification of malicious file placement in Print Spooler directories  
- Attribution of execution to trusted service processes  
- Analysis of DLL loading and execution chains  
- Correlation of process execution with outbound network connections  
- Validation of interactive reverse shell activity using packet capture  
- Confirmation of SYSTEM-level execution context  

The walkthrough highlights how legitimate Windows components can be abused to execute attacker code while blending into normal system activity.


### `images`

Contains screenshots supporting each investigative step, including:

- SMB access events targeting `spoolss`
- File creation evidence for malicious DLL placement
- Process execution and parent–child relationships
- Reverse shell network activity in Wireshark

These images provide visual confirmation of log evidence and analytical pivots.


### `case-report.md`

Provides the primary incident narrative documenting how service abuse led to code execution and post-exploitation activity.

Summarizes:

- Exploited service behavior  
- Execution confirmation  
- Network communication evidence  
- Final incident determination


### `detection-artifact-report.md`

Documents indicators related to:

- Abnormal service file writes  
- DLL execution via trusted services  
- Outbound connections from SYSTEM processes  

Supports development of host and network-based exploitation detections.


### `incident-response-report.md`

Focuses on remediation actions related to service exploitation, including:

- Host containment  
- Service configuration hardening  
- Malicious file removal  
- Network blocking considerations  

Reflects operational handling of service-based compromise scenarios.


### `incident-summary.md`

Provides a high-level overview of remote code execution through abuse of a trusted Windows service.

Intended for:

- IT leadership  
- Infrastructure teams  
- Compliance stakeholders  

Summarizes impact, privilege level achieved, and exposure risks resulting from service exploitation.


### `detection-and-hardening-recommendations.md`

Focuses on system configuration and service-level protections to reduce the risk of exploitation of trusted Windows services.

Includes recommendations covering:

- Print Spooler service exposure reduction and access restrictions  
- File system permissions for driver and service directories  
- Monitoring for abnormal DLL loading by service processes  
- Network segmentation and outbound traffic controls for servers  
- Patch management and service vulnerability mitigation strategies  

This file reflects how infrastructure and security teams document hardening and monitoring improvements following service exploitation incidents.


### `MITRE-ATT&CK-mapping.md`

Maps service exploitation, DLL execution, and command-and-control behavior to MITRE ATT&CK techniques using host and network telemetry.

Includes:

- Technique mappings for service abuse and execution  
- Evidence from process, file, and network artifacts  

Supports standardized classification of service-based exploitation activity.

---

## Intended Use

This investigation demonstrates how abuse of trusted Windows services can be identified using correlation of file system, process, service, and network telemetry. It emphasizes detection opportunities that remain visible even when attackers avoid deploying standalone malware executables.

---

## Relevance to Security Operations

Service abuse remains a high-impact intrusion technique because it leverages legitimate operating system functionality and often bypasses simplistic endpoint detections.

This investigation demonstrates how defenders can:

- Detect exploitation of native services
- Identify suspicious driver and DLL placement
- Attribute post-exploitation network activity
- Confirm privilege escalation using log and network evidence

Correlating these behaviors allows security teams to detect and respond to sophisticated intrusions that rely on trusted system components rather than custom malware.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation is intended to demonstrate structured host and network analysis, service abuse detection, and professional incident documentation aligned with operational security workflows.