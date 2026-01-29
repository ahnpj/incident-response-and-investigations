# Case Report — Windows Service Exploitation Investigation (Print Spooler Remote Code Execution)

**Case Type:** Endpoint Compromise / Service Abuse  
**Primary Abuse Pattern:** Abuse of Windows Print Spooler service to transfer and execute attacker-supplied DLL, resulting in SYSTEM-level reverse shell  
**Status:** Closed (investigation complete)  
**Confidence Level:** High — correlated Windows Security logs, Sysmon telemetry, and packet capture evidence

---

### 1) Executive Summary

This case investigates a Windows host compromise involving abuse of the Print Spooler service to deliver and execute an attacker-supplied DLL, resulting in remote code execution and establishment of a reverse shell running with SYSTEM-level privileges.

Host-based telemetry confirmed that the Print Spooler service (`spoolsv.exe`) accessed an attacker-controlled SMB resource, staged a malicious DLL within printer driver directories, and executed the payload through trusted Windows execution mechanisms. Network telemetry further validated outbound communication from the compromised host to attacker infrastructure, with packet capture confirming interactive command execution.

Correlated evidence across Windows Security logs, Sysmon process and file telemetry, and network traffic supports a service-abuse intrusion pattern leveraging native Windows components rather than custom malware binaries.

---

### 2) Incident Background

The investigation analyzed a simulated post-compromise scenario involving exploitation of Windows Print Services. Rather than reproducing exploit mechanics, the defensive objective was to reconstruct attacker behavior using available logs and network data, consistent with SOC post-incident workflows.

Because trusted Windows services can be abused to execute malicious code without dropping traditional malware artifacts, the investigation focused on identifying service-level abuse, file delivery mechanisms, and post-exploitation activity that would be observable to security monitoring platforms.

The investigation sought to determine:

- Which Windows service was abused
- How malicious files were transferred and staged
- Whether code execution occurred through trusted components
- Whether outbound command-and-control communication was established
- What artifacts are suitable for detection and response

---

### 3) Scope

This section defines which systems, identities, and data sources were included in the investigation, as well as what activity was not observed within the available evidence. Clearly defining scope helps distinguish confirmed service abuse and host compromise from assumptions about broader network intrusion that are not supported by telemetry.

#### ▶ 3.1) In-Scope

| Category | Included Items |
|--------|----------------|
| **Affected Windows Host** | • Compromised endpoint within `redteam.lab` domain |
| **Abused Service** | • Windows Print Spooler (`spoolsv.exe`) |
| **Primary Evidence Sources** | • Windows Security Event Logs<br>• Sysmon Operational Logs<br>• Network packet capture (PCAP) |
| **Behavioral Focus Areas** | • SMB-based service interaction<br>• File creation within printer driver directories<br>• Service-based execution of attacker-controlled DLLs<br>• Outbound network connections following execution |

#### ▶ 3.2) Out-of-Scope / Not Observed

- Exploit delivery mechanics
- Vulnerability exploitation details
- Malware binary analysis
- Additional lateral movement beyond observed host

Analysis was limited to post-exploitation artifacts available in the provided telemetry.

---

### 4) Environment

This investigation reconstructed service-level abuse of Windows Print Services resulting in remote code execution using host and network telemetry.

#### ▶ 4.1) **Affected System (Victim) Operating System:**
- Windows Server

#### ▶ 4.2) **Analyst Virtual Machine Operating System:**
- Windows-based analyst workstation used for log review and packet analysis

#### ▶ 4.3) **Platforms and Services:**
- Windows Print Spooler service — analyzed service interaction and driver installation behavior
- SMB file-sharing services — reviewed file transfer and named pipe access
- Packet capture analysis tools — validated reverse shell communication

#### ▶ 4.4) **Data Sources Reviewed:**
- Windows Security Event Logs (SMB access and service interaction)
- Sysmon Operational Logs
  - Process creation
  - File creation in printer driver directories
  - Network connections
- WireShark - network packet capture (PCAP)

**Analyst Note:**  
Exploit delivery mechanics were not analyzed. The investigation focuses on post-exploitation artifacts observable through service and process telemetry.

---

### 5) Evidence Summary

This section summarizes the primary evidence used to reconstruct service abuse, malicious payload staging, and post-exploitation activity observed during this incident. It focuses on how each data source contributed to understanding attacker behavior and impact rather than listing all raw log fields or detection logic.

Detailed event fields, SMB parameters, file paths, and detection-relevant artifacts extracted from this investigation are documented separately in: `detection-artifact-report.md`

This separation reflects common SOC workflows, where incident narratives and detection engineering references are maintained as distinct artifacts.


#### ▶ 5.1) SMB-Based Service Interaction — Print Spooler Access

Windows Security Event ID `5145` revealed remote SMB access to the `spoolss` named pipe over the `IPC$` share, indicating interaction with the Print Spooler service interface.

Relevant fields confirmed:

- Remote access to Print Spooler service
- Attacker-controlled source IP
- Repeated service interaction rather than single access

This behavior aligns with known Print Spooler abuse techniques that leverage SMB-based printer service interfaces.


#### ▶ 5.2) Malicious Payload Delivery — File Creation by Trusted Service

Sysmon Event ID `11` (FileCreate) events showed that `spoolsv.exe` wrote a non-standard DLL into printer driver staging directories:

`C:\Windows\System32\spool\drivers\x64\3\New\printevil.dll`

Legitimate printer driver components such as `unidrv.dll` and `winhttp.dll` were also observed during normal driver initialization. However, `printevil.dll` did not correspond to any legitimate Windows component and appeared only during the exploitation timeframe.

This confirms that the attacker leveraged the Print Spooler service to stage a custom DLL in a trusted system directory.


#### ▶ 5.3) Payload Execution — Trusted Binary Abuse

Sysmon process telemetry showed execution chains involving trusted Windows binaries, including:

- `spoolsv.exe` loading printer-related DLLs
- Follow-on execution using `rundll32.exe`

This execution model allows attacker-controlled code to run while blending into legitimate service activity and avoids obvious malicious process names.


#### ▶ 5.4) Outbound Communication — Reverse Shell Establishment

Sysmon Event ID `3` (NetworkConnect) confirmed that a system-level process initiated an outbound TCP connection to:

- **Destination IP:** `10.0.2.5`
- **Destination Port:** `443`

The initiating process was running as `NT AUTHORITY\SYSTEM`, confirming elevated execution context.

Packet capture analysis validated that this connection represented an interactive reverse shell session rather than transient network traffic.


#### ▶ 5.5) Post-Exploitation Validation — Privilege Confirmation

Network telemetry revealed interactive commands issued by the attacker after connection establishment. Execution of `whoami` returned:

`NT AUTHORITY\SYSTEM`

This confirms that exploitation resulted in full SYSTEM-level control of the host.

---

### 6) Investigation Timeline (Condensed)

The timeline below reflects the reconstructed sequence of attacker and host activity, not the step-by-step actions taken by the analyst during investigation. Detailed analyst workflow and tool usage are documented separately in: `investigation-walkthrough.md`  

This distinction mirrors real-world incident response reporting, where one timeline describes what happened, while another documents how it was discovered.

| Phase | Activity |
|--------|--------|
| T0 | Attacker accesses Print Spooler service over SMB |
| T1 | Malicious DLL transferred to printer driver directory |
| T2 | Print Spooler loads attacker-supplied DLL |
| T3 | Trusted Windows binaries execute payload |
| T4 | SYSTEM-level outbound connection established |
| T5 | Interactive reverse shell confirmed |
| T6 | Privilege validation commands executed |

---

### 7) Indicators of Compromise (IOCs)

The indicators listed below represent high-confidence artifacts associated with service abuse, malicious driver staging, and post-exploitation communication observed during this intrusion.

Field-level telemetry, SMB parameters, and example detection logic derived from these indicators are documented separately in: `detection-artifact-report.md`

That report is intended for SOC analysts and detection engineers responsible for implementing monitoring and alerting controls.


#### ▶ 7.1) Host-Based IOCs

These indicators identify the compromised endpoint and support scoping of affected systems.

- Host joined to `redteam.lab` domain
- Evidence of printer driver directory modification

**Detection Use Cases:**
- Identify hosts with new DLLs written to Print Spooler directories
- Scope additional systems with similar service activity


#### ▶ 7.2) Service Abuse & SMB IOCs

These indicators reflect remote interaction with Print Spooler service interfaces over SMB.

- SMB access to `IPC$` share
- `RelativeTargetName = spoolss`
- Windows Security Event ID `5145`

**Detection Use Cases:**
- Alert on SMB access targeting `spoolss`
- Detect Print Spooler service interaction from untrusted sources


#### ▶ 7.3) File System IOCs

These indicators represent malicious payload staging locations.

- Malicious DLL: `printevil.dll`
- Directory: `C:\Windows\System32\spool\drivers\x64\3\New\`

**Detection Use Cases:**
- Alert on non-standard DLLs written to printer driver paths
- Monitor service processes writing to system directories


#### ▶ 7.4) Process & Execution IOCs

These indicators reflect trusted binary abuse during payload execution.

- Parent process: `spoolsv.exe`
- Execution via `rundll32.exe`
- Abnormal parent-child process relationships

**Detection Use Cases:**
- Alert on `spoolsv.exe` spawning execution chains
- Detect trusted binaries executing from service contexts


#### ▶ 7.5) Network & C2 IOCs

These indicators reflect outbound communication following exploitation.

- Destination IP: `10.0.2.5`
- Destination Port: `443`
- Initiating process running as SYSTEM

**Detection Use Cases:**
- Alert on outbound connections from service processes
- Correlate service execution with network activity


#### ▶ 7.6) IOC Limitations

While the indicators above are high-confidence within this investigation, attackers can modify payload names, service interaction methods, and destination infrastructure. As a result, detection strategies should prioritize behavioral correlations such as service-based file creation followed by outbound network connections rather than relying solely on static indicators.

---

### 8) Case Determination

**Final Determination:**  
Confirmed Windows host compromise involving abuse of the Print Spooler service to transfer and execute attacker-controlled code, resulting in SYSTEM-level remote command execution and reverse shell communication.

Evidence supports a service-abuse intrusion pattern leveraging trusted Windows components rather than traditional malware installation mechanisms.

---

### 9) Recommended Follow-Ups (Case Closure Actions)

The recommendations below summarize key containment, hardening, and detection priorities based on behaviors observed during this incident. Detailed technical controls and expanded monitoring strategies are documented separately in: `detection-and-hardening-recommendations.md`

This section highlights immediate and high-impact actions, while the supporting report provides implementation-level detail.

#### ▶ 9.1) Immediate Containment

- Isolate the affected host from the network
- Disable Print Spooler service where not required
- Block outbound communication to identified attacker infrastructure

#### ▶ 9.2) Hardening

- Patch systems vulnerable to Print Spooler exploitation
- Restrict SMB access to service interfaces
- Limit driver installation paths used by services

#### ▶ 9.3) Detection

- Alert on SMB access targeting `spoolss`
- Monitor for new DLLs written by `spoolsv.exe`
- Correlate service activity with outbound network connections

---

### 10) Supporting Reports (In This Folder)

The files below make up the full case package for this investigation and provide additional detail across analyst workflow, response actions, detection engineering, and executive-level reporting.

- `investigation-walkthrough.md` — Step-by-step analyst workflow, screenshots, and investigative pivots
- `incident-summary.md` — Executive-level narrative and business impact
- `incident-response-report.md` — Containment, eradication, and recovery actions
- `detection-artifact-report.md` — Log fields, telemetry mapping, and detection pivots
- `detection-and-hardening-recommendations.md` — Preventive controls and monitoring improvements
- `MITRE-ATTACK-mapping.md` — Detailed technique mapping with evidence references
- `images/` — Screenshots and visual evidence
- `README.md` — High-level investigation overview

---

### 11) MITRE ATT&CK Mapping

The mappings below provide a high-level summary of confirmed adversary behaviors observed during this incident.

- Full investigative context and evidence references: `investigation-walkthrough.md`
- Expanded technique analysis and detection considerations: `MITRE-ATTACK-mapping.md`

#### ▶ 11.1) Technique Mapping

- **Initial Access — Ingress Tool Transfer (T1105)**
- **Execution — Service Execution (T1569.002)**
- **Defense Evasion — Masquerading (T1036)**
- **Command and Control — Application Layer Protocol: Web (T1071.001)**
- **Discovery — System Owner/User Discovery (T1033)**

#### ▶ 11.2) MITRE ATT&CK Mapping (Table View)

| Tactic | Technique | Description |
|--------|----------|-------------|
| Initial Access | **Ingress Tool Transfer (T1105)** | Malicious DLL transferred via SMB during service abuse |
| Execution | **Service Execution (T1569.002)** | Code executed through Print Spooler service |
| Defense Evasion | **Masquerading (T1036)** | Malicious DLL disguised as printer driver |
| Command and Control | **Application Layer Protocol: Web (T1071.001)** | Reverse shell over web protocol |
| Discovery | **System Owner/User Discovery (T1033)** | Privilege validation via command execution |

---

