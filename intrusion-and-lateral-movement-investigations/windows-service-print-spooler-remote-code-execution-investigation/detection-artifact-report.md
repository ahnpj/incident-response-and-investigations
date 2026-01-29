# Detection Artifact Report — Windows Service Exploitation Investigation (Print Spooler Remote Code Execution)

### 1) Purpose and Scope

This report documents **network, service, process, and persistence-related artifacts** observed during investigation of a Windows host compromise involving exploitation of the Print Spooler service for remote code execution (RCE). The purpose of this report is to provide **detection-engineering–ready indicators** that are directly tied to analyst investigation pivots and validation steps rather than isolated indicators of compromise.

Artifacts are mapped to how they were discovered during investigation, reflecting realistic SOC workflows where analysts pivot from network indicators to host-level confirmation and persistence validation.

All artifacts are derived from investigative steps documented in:

- `windows-service-abuse-remote-code-execution-investigation.md` — analyst pivots, Splunk queries, and validation workflow  
- `case-report.md` — reconstructed attacker activity timeline and impact assessment  
- `MITRE-ATT&CK-mapping.md` — technique classification and behavioral context  

This report complements:

- `incident-response-report.md` — containment, eradication, and recovery sequencing  
- `detection-and-hardening-recommendations.md` — preventive and monitoring controls  

---

### 2) Environment and Log Sources

This section summarizes telemetry sources used to identify and validate service exploitation artifacts.

#### ▶ 2.1) Primary telemetry sources referenced in investigation

- **Firewall and Network Logs**
  - Inbound SMB and RPC traffic to Print Spooler service ports
  - Source IP and session timing

- **Windows Security Event Log**
  - Event ID 4624 — Successful logon
  - Event ID 4672 — Special privileges assigned to new logon
  - Event ID 7045 — New service installed (if observed)

- **Sysmon (Microsoft Sysinternals)**
  - Event ID 1 — Process creation
  - Event ID 3 — Network connections
  - Event ID 11 — File creation

- **Splunk Endpoint and Network Data Models**
  - Endpoint.Processes
  - Endpoint.Filesystem
  - Network.Traffic

#### ▶ 2.2) Confirmed host

- **Victim system:** Windows server/workstation running Print Spooler  
- **Attack surface:** Network-exposed Print Spooler service

---

### 3) High-Confidence Investigation Anchors

This section lists timeline anchors that structured investigative correlation.

| Anchor Event | Description | Evidence Source | Investigation Pivot |
|--------|-------------|------------------|---------------------|
| Network exploitation attempt | External connection to spooler service | Firewall logs | Triggered service abuse investigation |
| Suspicious process spawn | Unexpected child process of spoolsv.exe | Sysmon Event ID 1 | Confirmed code execution |
| Payload file written | Executable dropped on disk | Sysmon Event ID 11 | Validated payload delivery |
| Service abuse persistence | Service or scheduled execution observed | Security logs / Sysmon | Identified persistence attempt |
| Continued execution | Repeated malicious processes | Sysmon Event ID 1 | Confirmed sustained compromise |

These anchors were used to pivot from network indicators into host-level execution and persistence validation.

---

### 4) Network and Service Exploitation Artifacts

This section documents network behaviors indicating exploitation of the Print Spooler service.

#### ▶ 4.1) Artifact: External Connections to Print Spooler Service Ports

**Observed Behavior:**

- Inbound network connections to RPC/SMB-related ports associated with Print Spooler activity.

**Where Identified in Investigation:**  
Analysts began investigation by reviewing firewall and network telemetry after alerts indicated abnormal inbound traffic to a server not typically accessed by external systems. Pivoting into port-level network logs showed repeated connection attempts to services associated with Print Spooler functionality, prompting hypothesis of service exploitation rather than standard file-sharing access.

**Behavioral Significance:**

- Suggests probing or exploitation of network-exposed service.
- Narrows attack vector to service-level vulnerability rather than phishing or credential abuse.

**Detection Guidance:**

- Alert on:
  - inbound connections to spooler-related ports from non-trusted networks
- Correlate with:
  - subsequent host-level execution events

---

### 5) Host Execution Artifacts — Confirmation of RCE

This section documents artifacts confirming successful code execution.

#### ▶ 5.1) Artifact: Unexpected Child Process Spawned by `spoolsv.exe`

**Observed Behavior:**

- Print Spooler service process spawning command shells or executables not part of normal print workflows.

**Where Identified in Investigation:**  
After identifying suspicious inbound network traffic, analysts pivoted to Sysmon Event ID 1 to inspect process trees involving `spoolsv.exe`. This revealed abnormal child processes launched under the service context, which should not occur during legitimate printing operations, confirming that remote code execution had been achieved.

**Behavioral Significance:**

- Direct confirmation of service exploitation leading to command execution.
- Eliminates false positives related to benign network scanning.

**Detection Guidance:**

- Alert when:
  - `spoolsv.exe` spawns shells or scripting engines
- Treat as:
  - high-severity host compromise


#### ▶ 5.2) Artifact: Creation of Executable Payload on Disk

**Observed Behavior:**

- New executable written to disk shortly before or after suspicious service-child execution.

**Where Identified in Investigation:**  
Following confirmation of abnormal child processes, analysts pivoted to Sysmon Event ID 11 around the same timestamps to determine whether a payload had been staged. This revealed newly created executable files in system or temporary directories, linking file creation directly to exploitation activity.

**Behavioral Significance:**

- Confirms attacker delivered tooling or malware.
- Provides artifact for containment and scoping.

**Detection Guidance:**

- Alert when:
  - executable files are created by service accounts
- Correlate with:
  - prior service process execution anomalies

---

### 6) Persistence and Post-Exploitation Artifacts

This section documents attacker actions to maintain access after exploitation.

#### ▶ 6.1) Artifact: Service Installation or Scheduled Execution

**Observed Behavior:**

- New service entries or repeated execution mechanisms observed following payload deployment.

**Where Identified in Investigation:**  
After confirming payload execution, analysts reviewed Windows Security and Sysmon telemetry to identify whether the attacker established persistence. Logs indicated service-related configuration changes and recurring process launches, suggesting attempts to retain access beyond the initial exploit session.

**Behavioral Significance:**

- Indicates attacker intent to maintain foothold.
- Elevates incident from transient exploit to sustained compromise.

**Detection Guidance:**

- Alert on:
  - new services installed by non-administrative workflows
- Correlate with:
  - recent exploitation indicators

---

### 7) Authentication and Privilege Context Artifacts

This section documents how execution aligned with privilege escalation.

#### ▶ 7.1) Artifact: Privileged Execution Context Following Exploitation

**Observed Behavior:**

- Processes executing with SYSTEM-level privileges shortly after network exploitation.

**Where Identified in Investigation:**  
Analysts correlated Sysmon process events with Security Event ID 4672 to confirm that processes spawned by the Print Spooler service inherited elevated privileges. This validated that exploitation granted high-integrity execution rather than limited user-level access.

**Behavioral Significance:**

- Enables full system control.
- Explains ability to install services and manipulate system files.

**Detection Guidance:**

- Alert when:
  - privileged processes are spawned from service contexts unexpectedly

---

### 8) Absence of Lateral Movement Artifacts

This section documents negative findings that influenced incident scoping.

#### ▶ 8.1) Artifact: No Evidence of Credential Theft or Network Propagation

**Observed Behavior:**

- No authentication attempts to other internal systems.
- No scanning or SMB connection attempts to peer hosts.

**Where Verified in Investigation:**  
Following confirmation of local compromise, analysts expanded review to include outbound network and authentication logs. No evidence of lateral movement was identified during the investigation window, supporting containment scope limited to the exploited host.

**Detection Implications:**

- Confirms localized compromise.
- Does not reduce severity due to SYSTEM-level access achieved.

---

### 9) Cross-Source Correlation Opportunities

This section outlines detection strategies based on investigation pivots.

#### ▶ 9.1) Correlation 1: Network Exploit Traffic → Service Child Process

**Signals:**

- Firewall inbound traffic to spooler ports
- Sysmon child process spawned by `spoolsv.exe`

**Use Case:**  
Detect active exploitation in progress.


#### ▶ 9.2) Correlation 2: Service Execution → Payload File Creation

**Signals:**

- Sysmon Event ID 1
- Sysmon Event ID 11

**Use Case:**  
Detect successful malware staging post-exploitation.


#### ▶ 9.3) Correlation 3: Payload Execution → Persistence Installation

**Signals:**

- Sysmon Event ID 1
- Security 7045 (service install) or recurring executions

**Use Case:**  
Detect transition from exploitation to durable compromise.

---

### 10) Indicator Reliability Considerations

This section distinguishes between fragile indicators and reliable behaviors.

**Low reliability indicators:**

- File names
- Service names

**Higher reliability indicators:**

- `spoolsv.exe` spawning shells or binaries
- Service-level file creation
- Network exploitation followed by host execution

Behavioral detection remains effective even when attackers modify payload names.

---

### 11) Closing Summary

This investigation demonstrated how exploitation of exposed Windows services can rapidly transition from:

- external network access
- to SYSTEM-level host compromise
- to establishment of persistence mechanisms

By correlating:

- inbound network telemetry,
- service process behavior,
- file creation activity,
- and privilege context,

analysts were able to confirm successful exploitation and scope impact accurately.

Detection strategies that monitor **service parent-child process relationships and correlate them with inbound network activity** can identify service exploitation attacks early, often before attackers complete post-exploitation objectives.

