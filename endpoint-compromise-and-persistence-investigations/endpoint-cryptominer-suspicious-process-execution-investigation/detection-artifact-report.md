# Detection Artifact Report — Endpoint Cryptominer Infection Investigation (Suspicious Process Execution and Resource Abuse)

### 1) Purpose and Scope

This report documents **host-based and process execution artifacts** observed during investigation of suspicious process activity on a Windows endpoint. The purpose of this report is to provide **detection-engineering–ready indicators** that are directly tied to analyst pivots and validation steps performed during the investigation.

Artifacts are mapped to how they were discovered during investigation, not simply listed as isolated indicators. This mirrors real SOC workflows where alerts are validated, expanded, and correlated across telemetry sources.

All artifacts are derived from investigative steps documented in:

- `suspicious-process-execution-investigation.md` — analyst pivots, queries, and evidence validation  
- `case-report.md` — reconstructed attacker activity timeline  
- `MITRE-ATT&CK-mapping.md` — technique classification and behavioral context  

This report complements:

- `incident-response-report.md` — response sequencing and remediation rationale  
- `detection-and-hardening-recommendations.md` — preventive and monitoring controls  

---

### 2) Environment and Log Sources

This section summarizes the telemetry sources used to identify and validate suspicious execution activity.

#### ▶ 2.1) Primary telemetry sources referenced in investigation

- **Sysmon (Microsoft Sysinternals)**
  - Event ID 1 — Process creation
  - Event ID 11 — File creation
  - Event ID 13 — Registry value modification

- **Windows Security Event Log**
  - Event ID 4624 — Successful logon
  - Event ID 4688 — Process creation (native)

- **Splunk Endpoint Data Models**
  - Endpoint.Processes
  - Endpoint.Registry
  - Endpoint.Filesystem

#### ▶ 2.2) Confirmed host:

- **Victim system:** Windows workstation (lab host)  
- **User context:** Local user account active during suspicious execution

---

### 3) High-Confidence Investigation Anchors

This section lists timeline anchors that structured investigative correlation.

| Anchor Event | Description | Evidence Source | Investigation Pivot |
|--------|-------------|------------------|---------------------|
| Initial suspicious alert | Abnormal process execution detected | SIEM query | Triggered host investigation |
| Process tree anomaly | Parent-child mismatch | Sysmon + Splunk | Led to file validation |
| Dropped file | New executable written to disk | Sysmon Event ID 11 | Confirmed payload staging |
| Persistence attempt | Registry Run key modified | Sysmon Event ID 13 | Identified durable execution |
| Continued execution | Repeated process launches | Sysmon Event ID 1 | Validated persistence behavior |

These anchors were used to pivot across host telemetry and confirm malicious execution rather than benign administrative activity.

---

### 4) Initial Suspicious Process Detection Artifacts

This section documents the artifacts that triggered investigation.

#### ▶ 4.1) Artifact: Abnormal Process Creation Pattern

**Observed Behavior:**

- Execution of a suspicious binary with no known legitimate software association.
- Parent process did not align with expected user-launched or system processes.

**Where Identified in Investigation:**  
Analysts began by reviewing SIEM alerts and endpoint process summaries highlighting unusual executable names. From there, they pivoted into Sysmon Event ID 1 data using Splunk to reconstruct the full process tree. This revealed that the suspicious process was spawned by an unexpected parent process rather than by standard application launch mechanisms, prompting deeper investigation into how the binary arrived on the system.

**Behavioral Significance:**

- Indicates potential malicious execution rather than legitimate software installation.
- Parent-child anomalies often signal LOLBIN abuse or staged payload execution.

**Detection Guidance:**

- Alert when:
  - executable names are not associated with installed software inventory
  - parent process does not match expected installers or shells

---

### 5) File System Artifacts — Payload Staging

This section documents artifacts related to malware delivery and staging.

#### ▶ 5.1) Artifact: Creation of Executable File Prior to Execution

**Observed Behavior:**

- New executable written to disk shortly before suspicious execution.

**Where Identified in Investigation:**  
After identifying the abnormal process execution, analysts pivoted to Sysmon Event ID 11 data around the execution timestamp to determine whether the file had been newly created. This revealed that the executable was written to disk minutes before it was launched, confirming that the binary was not a long-standing system file and was likely delivered as part of malicious activity.

**Behavioral Significance:**

- Strong indicator of payload staging.
- Links file delivery directly to execution event.

**Detection Guidance:**

- Alert when:
  - new executable files are created in user-writable directories
- Correlate with:
  - subsequent process execution events referencing the same file

---

### 6) Process Execution Artifacts — Malicious Activity Validation

This section documents indicators that validated the execution was malicious.

#### ▶ 6.1) Artifact: Repeated Execution of the Same Binary

**Observed Behavior:**

- Multiple process creation events for the same suspicious executable.

**Where Identified in Investigation:**  
Analysts expanded the time window around the initial execution and observed repeated Sysmon Event ID 1 entries for the same file path. This repetition suggested automated or persistent execution rather than a one-time accidental launch, increasing confidence that the activity was malicious.

**Behavioral Significance:**

- Suggests persistence or repeated task execution.
- Differentiates malicious tooling from accidental user execution.

**Detection Guidance:**

- Alert when:
  - same unusual binary executes repeatedly in short intervals
- Increase severity when:
  - combined with persistence artifacts

---

### 7) Persistence Mechanism Artifacts

This section documents how the attacker attempted to maintain execution across sessions.

#### ▶ 7.1) Artifact: Registry Run Key Value Creation

**Observed Behavior:**

- New registry value created under user-level Run key pointing to suspicious executable.

**Where Identified in Investigation:**  
Following confirmation of repeated execution, analysts pivoted into registry telemetry using Sysmon Event ID 13 to determine whether an autorun mechanism had been established. This revealed new Run key entries referencing the same executable observed in earlier process and file creation events, confirming that persistence had been intentionally configured.

**Behavioral Significance:**

- Enables automatic execution at user logon.
- Confirms attacker intent for long-term access.

**Detection Guidance:**

- Alert on:
  - new Run key values referencing user directory executables
- Correlate with:
  - recent file creation and process execution events

---

### 8) Authentication and User Context Artifacts

This section documents how execution was tied to user activity.

#### ▶ 8.1) Artifact: Execution Occurring Under User Logon Session

**Observed Behavior:**

- Suspicious processes executed shortly after user logon events.

**Where Identified in Investigation:**  
Analysts correlated process creation timestamps with Windows Security Event ID 4624 (successful logon) to determine whether execution occurred in an active user session. This confirmed that execution aligned with user logon activity rather than background system tasks, suggesting that persistence was designed to trigger at interactive logon.

**Behavioral Significance:**

- Supports registry Run key persistence hypothesis.
- Indicates attacker targeting user context rather than system service.

**Detection Guidance:**

- Alert when:
  - suspicious processes execute immediately after user logon
- Correlate with:
  - registry autorun creation

---

### 9) Absence of Lateral Movement Artifacts

This section documents negative findings that influenced scoping decisions.

#### ▶ 9.1) Artifact: No Evidence of Network-Based Propagation

**Observed Behavior:**

- No abnormal outbound connections.
- No authentication attempts to other systems.

**Where Verified in Investigation:**  
Analysts reviewed network telemetry and authentication logs to determine whether the host was used to pivot to other systems. No outbound scanning, authentication attempts, or lateral movement indicators were observed during the investigation window.

**Detection Implications:**

- Confirms compromise scope was limited to single host.
- Does not reduce severity due to confirmed persistence and execution.

---

### 10) Cross-Source Correlation Opportunities

This section outlines detection strategies based on investigation pivots.

#### ▶ 10.1) Correlation 1: File Creation → Process Execution

**Signals:**

- Sysmon Event ID 11 (FileCreate)
- Sysmon Event ID 1 (ProcessCreate)

**Use Case:**  
Detect payload staging immediately followed by execution.


#### ▶ 10.2) Correlation 2: Process Execution → Registry Persistence

**Signals:**

- Sysmon Event ID 1
- Sysmon Event ID 13

**Use Case:**  
Detect execution followed by autorun establishment.


#### ▶ 10.3) Correlation 3: User Logon → Suspicious Process Execution

**Signals:**

- Security Event ID 4624
- Sysmon Event ID 1

**Use Case:**  
Detect persistence triggers tied to interactive sessions.

---

### 11) Indicator Reliability Considerations

This section distinguishes between easily changed indicators and reliable behavioral patterns.

**Low reliability indicators:**

- File names
- Folder paths

**Higher reliability indicators:**

- Execution shortly after file creation
- Run key persistence creation
- Repeated execution across logon sessions

Behavior-based detection remains effective even when attackers change filenames or locations.

---

### 12) Closing Summary

This investigation demonstrated how suspicious execution can be confirmed through systematic correlation of:

- process creation telemetry
- file creation events
- registry persistence mechanisms
- user logon timing

By following a structured pivot workflow, analysts were able to move from a single suspicious alert to confirmation of:

- malicious payload staging
- durable persistence
- repeated execution under user context

Detection strategies that correlate these behaviors can reliably identify similar threats before they escalate into broader system compromise.

