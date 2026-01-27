# Windows Service Exploitation Investigation (Print Spooler Remote Code Execution)

**Category:** Intrusion and Lateral Movement  
**Primary Attack Surface:** Network-accessible Windows services  
**Tactics Observed:** Initial Access, Privilege Escalation, Execution, Lateral Movement  
**Primary Data Sources:** Windows Event Logs, Sysmon Process and Network Events, Network Packet Capture (PCAP)

---

### Overview

This investigation analyzes abuse of a trusted Windows service that resulted in unauthorized file transfer, remote code execution, and establishment of a reverse shell connection. The attacker leveraged native Windows components to execute malicious code and communicate with external infrastructure without deploying custom executables.

The analysis focuses on reconstructing attacker behavior using correlated host-based telemetry and network traffic, with emphasis on how legitimate Windows services can be abused to deliver payloads, execute code, and establish command-and-control channels.

The investigation demonstrates how an analyst:
- Identifies service abuse through SMB and file system telemetry
- Distinguishes malicious driver files from legitimate Windows components
- Confirms execution of attacker-supplied code through trusted services
- Correlates host execution with network-level command-and-control activity

---

### What This Investigation Covers

This case simulates post-compromise analysis following exploitation of the Windows Print Spooler service. The vulnerable condition and exploit execution occurred prior to analysis; the investigation focuses on reconstructing attacker behavior from collected host and network telemetry.

The investigation identifies SMB access targeting the `spoolss` named pipe, confirms file transfer from attacker-controlled infrastructure, detects malicious DLL placement in Print Spooler driver directories, attributes execution to the Print Spooler service (`spoolsv.exe`), identifies use of `rundll32.exe` to load attacker-controlled code, correlates execution with outbound network connections, confirms interactive reverse shell activity via packet capture, and verifies SYSTEM-level execution context using post-exploitation commands.

Rather than focusing on exploit mechanics, the walkthrough emphasizes defender-visible artifacts that remain observable after exploitation.

---

### How to Navigate This Investigation

This case is documented across multiple focused reports to reflect how service exploitation incidents are handled in real SOC and incident response workflows. Supporting reports provide incident summaries, response actions, detection artifacts, and security improvement recommendations. A breakdown of each file is provided below.

If you want to follow the investigation step by step, start with:

**`investigation-walkthrough.md`**

---

### Repository Structure & Supporting Documents

All investigation outputs are separated into focused reports aligned with common incident documentation practices.

| File / Folder | Purpose | Contents and Focus |
|-------------|--------|--------------------|
| `investigation-walkthrough.md` | Host and network correlation walkthrough focused on reconstructing exploitation of a trusted Windows service and post-exploitation activity. | Documents detection of service-related SMB access patterns, identification of malicious file placement in Print Spooler directories, attribution of execution to trusted service processes, analysis of DLL loading and execution chains, correlation of process execution with outbound network connections, validation of interactive reverse shell activity using packet capture, and confirmation of SYSTEM-level execution context. Highlights how legitimate Windows components can be abused to execute attacker code while blending into normal system activity. |
| `images/` | Visual evidence supporting each investigative step and analytical pivot. | Contains screenshots of SMB access events targeting `spoolss`, file creation evidence for malicious DLL placement, process execution and parent–child relationships, and reverse shell network activity captured in Wireshark. |
| `case-report.md` | Primary incident narrative documenting how service abuse led to code execution and post-exploitation activity. | Summarizes exploited service behavior, execution confirmation, network communication evidence, and final incident determination in a case-style format suitable for tracking and escalation. |
| `detection-artifact-report.md` | Detection-relevant indicators derived from service exploitation and post-exploitation behavior. | Documents abnormal service file writes, DLL execution via trusted services, and outbound connections from SYSTEM processes to support development of host- and network-based exploitation detections. |
| `incident-response-report.md` | Operational remediation actions following service exploitation. | Covers host containment, service configuration hardening, malicious file removal, and network blocking considerations reflecting response handling for service-based compromise scenarios. |
| `incident-summary.md` | Executive-level overview of remote code execution through abuse of a trusted Windows service. | Summarizes impact, privilege level achieved, and exposure risks resulting from service exploitation for IT leadership, infrastructure teams, and compliance stakeholders. |
| `detection-and-hardening-recommendations.md` | Service-level protections and monitoring improvements to reduce exploitation risk. | Includes recommendations covering Print Spooler exposure reduction and access restrictions, file system permissions for driver and service directories, monitoring for abnormal DLL loading by service processes, network segmentation and outbound traffic controls for servers, and patch management strategies for service vulnerabilities. |
| `MITRE-ATT&CK-mapping.md` | Mapping of service exploitation and command-and-control behavior to MITRE ATT&CK techniques. | Maps service abuse, DLL execution, and command-and-control activity using evidence from process, file, and network artifacts to support standardized classification of service-based exploitation activity. |

---

### Environment, Data Sources, and Tools

This investigation analyzes service-level exploitation of Windows Print Services resulting in remote code execution and interactive shell access using correlated host and network telemetry.

#### Environment and Investigation Scope (At a Glance)

| Area | Details |
|------|---------|
| **Environment Type** | Windows Server (service exploitation investigation) |
| **Affected Assets** | Print Spooler service, SMB file services, and exploit-triggered process and service activity |
| **Victim Operating System** | Windows Server hosting the Print Spooler service abused to install malicious printer drivers and execute attacker-controlled code |
| **Analyst Operating System** | Windows-based analyst workstation used to query SIEM telemetry and analyze packet capture data |
| **Primary Platforms / Services** | Windows Print Spooler service, SMB file services, Splunk SIEM platform |
| **Investigation Focus** | Validate Print Spooler exploitation leading to attacker-controlled code execution and post-exploitation activity |

#### Data Sources, Evidence, and Analysis Techniques

| Area | Details |
|------|---------|
| **Primary Telemetry Sources** | Windows Security Event Logs, Sysmon operational logs, and network packet capture (PCAP) |
| **SMB and Service Interaction Evidence** | Windows Security telemetry showing SMB access patterns and service-related interactions around the driver installation window |
| **File Placement Evidence** | Sysmon file creation events confirming malicious DLL placement in Print Spooler driver directories |
| **Execution Chain Evidence** | Sysmon process creation telemetry attributing execution to `spoolsv.exe` and identifying `rundll32.exe` loading attacker-controlled code |
| **Network Callback Evidence** | Sysmon network events and PCAP validation showing outbound connections associated with reverse shell activity |
| **Wireshark Validation** | Packet-level confirmation of reverse shell establishment, interactive command execution, and attacker-controlled communication patterns |
| **Splunk Correlation Techniques** | SPL pivots across Security and Sysmon logs to correlate file creation, process execution, and post-exploitation activity |
| **PowerShell Validation** | Supporting checks for dropped file presence and additional staging or persistence indicators as documented in the investigation |
| **Manual Timeline Correlation** | Alignment of SMB file transfer, driver installation, execution events, and network callbacks into a coherent exploitation sequence |

This investigation demonstrates how service exploitation can be reconstructed using combined host and network telemetry, even when exploit delivery mechanics are not directly observable in logs.

---

### Intended Use

This investigation demonstrates how abuse of trusted Windows services can be identified using correlation of file system, process, service, and network telemetry. It emphasizes detection opportunities that remain visible even when attackers avoid deploying standalone malware executables.

---

### Relevance to Security Operations

Service abuse remains a high-impact intrusion technique because it leverages legitimate operating system functionality and can bypass simplistic endpoint detections.

This investigation demonstrates how defenders can detect exploitation of native services, identify suspicious driver and DLL placement, attribute post-exploitation network activity, and confirm privileged execution context using correlated host and network evidence. Correlating these behaviors enables detection and response to intrusions that rely on trusted system components rather than custom malware.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation is intended to demonstrate structured host and network analysis, service abuse detection, and professional incident documentation aligned with operational security workflows.

