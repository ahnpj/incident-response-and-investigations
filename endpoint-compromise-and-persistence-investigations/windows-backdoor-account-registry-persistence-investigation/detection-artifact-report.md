# Detection Artifact Report — Windows Host Compromise Investigation (Backdoor Account Creation and Registry-Based Persistence)

### 1) Purpose and Scope

This report documents **host-based identity, process, and registry artifacts** observed during investigation of a Windows host compromise involving unauthorized local account creation and registry-based persistence. The purpose of this report is to provide **detection-engineering–ready indicators** that are explicitly tied to analyst investigation pivots and validation steps rather than generic indicators of compromise.

Artifacts are mapped to how they were discovered during investigation, reflecting realistic SOC workflows where analysts move from one signal to another to confirm malicious behavior.

All artifacts are derived from investigative steps documented in:

- `windows-backdoor-account-registry-persistence-investigation.md` — analyst pivots, commands, and validation workflow  
- `case-report.md` — reconstructed attacker activity timeline  
- `MITRE-ATT&CK-mapping.md` — technique classification and behavioral context  

This report complements:

- `incident-response-report.md` — containment, eradication, and recovery procedures  
- `detection-and-hardening-recommendations.md` — preventive and monitoring controls  

---

### 2) Environment and Log Sources

This section summarizes the telemetry sources used to identify and validate compromise artifacts.

#### ▶ 2.1) Primary telemetry sources referenced in investigation

- **Windows Security Event Log**
  - Event ID 4720 — User account created
  - Event ID 4726 — User account deleted
  - Event ID 4732 — Member added to local Administrators group
  - Event ID 4624 — Successful logon

- **Sysmon (Microsoft Sysinternals)**
  - Event ID 1 — Process creation
  - Event ID 13 — Registry value modification

- **Splunk Endpoint Data Models**
  - Endpoint.Users
  - Endpoint.Processes
  - Endpoint.Registry

#### ▶ 2.2) Confirmed host

- **Victim system:** Windows workstation (lab host)  
- **Security context:** Local administrative privileges abused

---

### 3) High-Confidence Investigation Anchors

This section lists timeline anchors that structured investigative correlation.

| Anchor Event | Description | Evidence Source | Investigation Pivot |
|--------|-------------|------------------|---------------------|
| New account detected | Local user created | Security 4720 | Triggered identity review |
| Privilege escalation | Account added to Administrators | Security 4732 | Confirmed elevated persistence |
| Malware execution | Suspicious binary launched | Sysmon 1 | Led to persistence hunting |
| Registry autorun | Run key modified | Sysmon 13 | Confirmed durable persistence |
| Cleanup action | User account deleted | Security 4726 | Indicated defense evasion |

These anchors were used to pivot between identity, execution, and persistence telemetry.

---

### 4) Identity and Account Manipulation Artifacts

This section documents identity-related indicators confirming attacker persistence.

#### ▶ 4.1) Artifact: Unauthorized Local User Account Creation

**Observed Behavior:**

- New local user account created that did not align with provisioning workflows.

**Where Identified in Investigation:**  
Analysts began by reviewing Windows Security Event ID 4720 events to identify unexpected local account creations. This was triggered after suspicious system behavior prompted identity review. Once a new account was identified, analysts pivoted to determine whether the account had elevated privileges or was associated with other suspicious activity.

**Behavioral Significance:**

- Indicates attacker attempting to establish persistent access independent of initial credentials.
- Local account creation on workstations is rarely legitimate outside IT provisioning.

**Detection Guidance:**

- Alert on:
  - any local user creation on endpoints
- Correlate with:
  - recent suspicious process execution or logon anomalies

#### ▶ 4.2) Artifact: Privilege Escalation via Administrators Group Membership

**Observed Behavior:**

- Newly created account added to local Administrators group.

**Where Identified in Investigation:**  
After identifying unauthorized account creation, analysts pivoted to group membership change events (Security Event ID 4732) to determine whether the account had been granted elevated privileges. Security logs confirmed that the new account was added to administrative groups shortly after creation, validating intent to maintain privileged persistence.

**Behavioral Significance:**

- Converts basic access into full host control.
- Enables tampering with security controls and further persistence mechanisms.

**Detection Guidance:**

- Alert when:
  - new accounts are added to Administrators
- Increase severity when:
  - addition occurs shortly after account creation

---

### 5) Process Execution Artifacts

This section documents host execution behaviors that supported compromise validation.

#### ▶ 5.1) Artifact: Suspicious Process Execution Associated with Persistence Setup

**Observed Behavior:**

- Execution of non-standard binaries not associated with installed software.

**Where Identified in Investigation:**  
Following confirmation of identity abuse, analysts pivoted into Sysmon Event ID 1 telemetry to identify processes executed under the compromised context. This review revealed suspicious binaries executed shortly after account creation and privilege escalation, suggesting that attackers were configuring persistence mechanisms or deploying tooling.

**Behavioral Significance:**

- Confirms attacker actively interacted with host post-compromise.
- Links identity persistence to malware or tooling execution.

**Detection Guidance:**

- Alert when:
  - uncommon executables run under newly created accounts
- Correlate with:
  - identity manipulation events

---

### 6) Registry Persistence Artifacts

This section documents registry-based mechanisms used to maintain execution across logons.

#### ▶ 6.1) Artifact: Registry Run Key Value Creation

**Observed Behavior:**

- New registry values added under user or system Run keys pointing to suspicious executables.

**Where Identified in Investigation:**  
After identifying suspicious execution activity, analysts pivoted into Sysmon Event ID 13 records to determine whether autorun mechanisms were established. Registry telemetry showed new Run key values referencing the same executables observed in process creation events, confirming that persistence was intentionally configured rather than incidental.

**Behavioral Significance:**

- Enables malware or tooling to execute automatically at logon.
- Indicates attacker intent for long-term access.

**Detection Guidance:**

- Alert on:
  - new Run key values referencing user-writable paths
- Correlate with:
  - recent process execution of the same binary

---

### 7) Account Cleanup and Defense Evasion Artifacts

This section documents attacker actions intended to reduce forensic visibility.

#### ▶ 7.1) Artifact: Deletion of Local User Account

**Observed Behavior:**

- Local user account deleted after persistence mechanisms were established.

**Where Identified in Investigation:**  
After confirming persistence, analysts reviewed Security Event ID 4726 to determine whether any accounts had been removed. Logs showed deletion of a local account after registry persistence was in place, suggesting the attacker attempted to remove initial access artifacts while retaining durable control via autoruns.

**Behavioral Significance:**

- Indicates defense evasion and attempt to reduce traceability.
- Suggests attacker confidence that persistence remains intact.

**Detection Guidance:**

- Alert on:
  - unexpected local account deletions
- Correlate with:
  - prior account creation and persistence events

---

### 8) Authentication and Session Context Artifacts

This section documents how execution aligned with user sessions.

#### ▶ 8.1) Artifact: Execution Tied to User Logon Sessions

**Observed Behavior:**

- Suspicious processes executed shortly after user logon events.

**Where Identified in Investigation:**  
Analysts correlated Sysmon process creation timestamps with Windows Security Event ID 4624 (successful logon) to determine whether execution aligned with interactive sessions. This supported the conclusion that registry Run keys were triggering execution during user logons.

**Behavioral Significance:**

- Validates effectiveness of persistence mechanism.
- Indicates attacker targeting user-session execution rather than system services.

**Detection Guidance:**

- Alert when:
  - suspicious binaries execute immediately after logon
- Correlate with:
  - recent registry autorun modifications

---

### 9) Absence of Lateral Movement Artifacts

This section documents negative findings that influenced scoping decisions.

#### ▶ 9.1) Artifact: No Evidence of Network-Based Propagation

**Observed Behavior:**

- No abnormal outbound scanning.
- No authentication attempts to other internal hosts.

**Where Verified in Investigation:**  
Analysts reviewed firewall and authentication telemetry to determine whether the compromised system was used to pivot to other hosts. No evidence of lateral movement was observed within the investigation window, supporting a single-host compromise scope.

**Detection Implications:**

- Confirms localized compromise.
- Does not reduce severity due to confirmed persistence and privilege abuse.

---

### 10) Cross-Source Correlation Opportunities

This section outlines detection strategies reflecting investigation pivots.

#### ▶ 10.1) Correlation 1: Account Creation → Admin Group Addition

**Signals:**

- Security 4720
- Security 4732

**Use Case:**  
Detect privileged persistence via identity manipulation.


#### ▶ 10.2) Correlation 2: Admin Account Activity → Suspicious Process Execution

**Signals:**

- Security 4624 (logon)
- Sysmon 1 (process creation)

**Use Case:**  
Detect attacker-controlled sessions executing tools.


#### ▶ 10.3) Correlation 3: Process Execution → Registry Persistence

**Signals:**

- Sysmon 1
- Sysmon 13

**Use Case:**  
Detect establishment of autorun mechanisms.

#### ▶ 10.4) Correlation 4: Persistence Established → Account Deletion

**Signals:**

- Sysmon 13
- Security 4726

**Use Case:**  
Detect cleanup actions following persistence setup.

---

### 11) Indicator Reliability Considerations

This section distinguishes between easily modified indicators and reliable behaviors.

**Low reliability indicators:**

- Usernames
- File names
- Registry value names

**Higher reliability indicators:**

- Sequence of account creation → privilege escalation → persistence setup
- Correlation of execution with logon sessions
- Cleanup actions following persistence

Behavior-based detection remains resilient even when attackers change identifiers.

---

### 12) Closing Summary

This investigation demonstrated how attackers can maintain long-term access to a Windows host by combining:

- identity persistence (local account creation and privilege escalation)
- execution of attacker-controlled binaries
- registry-based autorun mechanisms
- cleanup actions to reduce traceability

By correlating identity events, process execution telemetry, and registry modifications, analysts were able to reconstruct the full persistence strategy and confirm durable compromise.

Detection strategies that focus on **behavioral sequences rather than isolated events** can reliably detect similar intrusions even when attackers modify filenames or account names.

