# Case Report — Windows Host Compromise Investigation (Backdoor Account Creation and Registry-Based Persistence)

**Case Type:** Endpoint Compromise / Unauthorized Account Creation  
**Primary Abuse Pattern:** Backdoor local account creation via WMIC with registry-based persistence artifacts and follow-on encoded PowerShell execution  
**Status:** Closed (investigation complete)  
**Confidence Level:** High — correlated Security, Sysmon/registry, and PowerShell telemetry

---

### 1) Executive Summary

This case investigates a suspected Windows host compromise involving unauthorized local account creation, registry artifacts under the SAM hive consistent with account persistence, and follow-on encoded PowerShell execution contacting an external web resource.

Log analysis confirmed that a backdoor local account (`A1berto`) was created remotely using WMIC to execute `net user /add` on the target host. Registry telemetry showed new entries under SAM hive paths associated with the created account, confirming that Windows registered the backdoor identity. Subsequent PowerShell activity originating from a different host revealed encoded commands that, once decoded, contacted an external PHP endpoint.

Correlated evidence across Windows Security logs, Sysmon/registry events, and PowerShell telemetry supports a multi-stage intrusion involving persistence via account creation, impersonation through look-alike usernames, remote execution using living-off-the-land tools, and outbound command-and-control communication.

---

### 2) Incident Background

The investigation was initiated based on suspicious activity observed in pre-ingested Windows telemetry within Splunk, treated as if it were received following an alert on a Windows workstation. Because adversaries commonly establish persistence through local account creation and abuse built-in management tools, the analysis focused on validating whether a backdoor account existed and whether additional post-compromise activity occurred.

The investigation aimed to determine:

- Whether a new local account was created and by what method
- Whether registry artifacts supported persistence or identity registration
- Whether impersonation of a legitimate user was attempted
- Whether follow-on execution and outbound communication occurred

---

### 3) Scope

This section defines which systems, identities, and data sources were included in the investigation, as well as what was not observed within the available evidence. Clearly defining scope helps distinguish confirmed activity from assumptions and prevents over-attribution beyond what the telemetry supports.


#### In-Scope

| Category | Included Items |
|--------|-----------------|
| **Affected Windows Hosts** | • `Micheal.Beaven` — account creation and registry activity<br>• `James.browne` — PowerShell execution activity |
| **Backdoor Account** | • `A1berto` |
| **Primary Evidence Sources** | • Windows Security Event Logs<br>• Sysmon registry telemetry<br>• PowerShell engine and pipeline logs |
| **Behavioral Focus Areas** | • Local account creation<br>• Registry persistence artifacts<br>• Remote execution tooling<br>• Encoded PowerShell activity |


#### Out-of-Scope / Not Observed

| Category | Not Included / Not Observed |
|--------|------------------------------|
| **Malware File Analysis** | No static or dynamic malware analysis performed |
| **Network Packet Capture** | No PCAP or deep packet inspection available |
| **Additional Lateral Movement** | No movement observed beyond WMIC-based remote execution |

Analysis was limited to telemetry contained within the dataset and did not involve direct interaction with the affected endpoints.

---

### 4) Environment

This investigation reconstructed unauthorized account creation and registry-based persistence using Windows host telemetry.

| Category | Details |
|--------|--------|
| **Affected System (Victim) OS** | • Windows workstation |
| **Analyst VM OS** | • Windows-based analyst workstation used for host log and registry analysis |
| **Platforms & Services** | • Windows authentication subsystem — reviewed local user and group changes<br>• Windows registry autorun mechanisms — analyzed persistence configuration |
| **Data Sources Reviewed** | **Windows Security Event Logs:**<br>• Account creation (4720)<br>• Group membership changes (4732)<br><br>**Sysmon Operational Logs:**<br>• Process creation<br>• Registry value modifications<br><br>**File System Artifacts:**<br>• Binary locations and timestamps |

**Analyst Note:**  
The investigation focuses on post-access host activity rather than initial access mechanisms.

---

### 5) Evidence Summary

This section summarizes the primary evidence used to reconstruct identity abuse, registry-based persistence, and follow-on execution activity observed during this Windows host compromise. It focuses on how each data source contributed to understanding attacker behavior and impact rather than listing all raw log fields or detection logic.

Detailed event fields, registry parameters, authentication attributes, and detection-relevant artifacts extracted from this investigation are documented separately in: `detection-artifact-report.md`

This separation reflects common SOC workflows, where incident narratives and detection engineering references are maintained as distinct artifacts.

<hr width="30%">

#### 5.1) Backdoor Account Creation — Command-Line Evidence

Process creation telemetry revealed execution of the following command:

`net user /add Alberto paw0rd1`

This command was observed across multiple log sources, including:

- **Event ID 4688 (Windows Security):** Captured full command line and execution context
- **Event ID 1 (Sysmon):** Recorded process creation with parent process metadata
- **Event ID 800:** Logged script/engine-level execution context

The use of `/add` with a clear-text password strongly indicated unauthorized account creation using built-in Windows utilities rather than legitimate provisioning workflows.

<hr width="30%">

#### 5.2) Account Management Confirmation — Security Event Correlation

Windows account management logs confirmed the creation of a new local account:

- **Backdoor account created:** `A1berto`

Security Event ID `4720` validated that Windows successfully registered the account. Correlation between command-line execution and account management telemetry confirmed that the observed process execution resulted in persistent identity creation on the host.

<hr width="30%">

#### 5.3) Registry Artifact Correlation — SAM Hive Persistence

Registry telemetry revealed creation of keys under the SAM hive associated with the backdoor account:

`HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

These artifacts confirm that Windows wrote account metadata consistent with local account registration. The `TargetObject` field in registry events was critical for identifying the specific persistence-relevant key, allowing direct attribution to the created backdoor user.

<hr width="30%">

#### 5.4) Impersonation Intent — Look-Alike Username Pattern

Review of user naming patterns revealed that the legitimate user:

- `Alberto`

closely resembled the attacker-created account:

- `A1berto`

This single-character substitution is a common masquerading technique used to blend into normal activity and reduce detection during log review or user enumeration.

<hr width="30%">

#### 5.5) Remote Execution — WMIC Abuse

Process creation telemetry revealed that account creation was performed remotely using WMIC:

`C:\Windows\System32\Wbem\WMIC.exe /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"`

This confirms that the adversary:

- Operated remotely
- Used living-off-the-land administrative tooling
- Did not require interactive login to the target host

WMIC abuse is a common lateral movement and remote administration technique in Windows intrusions.

<hr width="30%">

#### 5.6) Backdoor Account Usage — Authentication Review

Searches for logon activity associated with the backdoor account revealed:

- No successful (`4624`) or failed (`4625`) logon events for `A1berto`

This indicates that while the account was created successfully, it was not actively used for authentication during the observed timeframe, suggesting it may have been staged for future access or persistence.

<hr width="30%">

#### 5.7) PowerShell Activity — Encoded Execution and Host Attribution

PowerShell telemetry identified encoded command execution originating from:

- **Host:** `James.browne`

Event ID `4103` indicated **79 PowerShell engine events**, suggesting repeated or multi-stage script execution.

PowerShell `-enc` parameters contained Base64-encoded payloads with multiple decoding layers. After decoding, the payload resolved to outbound web communication with:

- Raw URL: `http://10.10.10.5/news.php`
- Defanged: `hxxp[://]10[.]10[.]10[.]5/news[.]php`

This confirmed follow-on command-and-control style communication separate from the account creation activity.

---

### 6) Investigation Timeline (Condensed)

The timeline below reflects the reconstructed sequence of attacker and host activity, not the step-by-step actions taken by the analyst during investigation. Detailed analyst workflow and tool usage are documented separately in: `investigation-walkthrough.md`  

This distinction mirrors real-world incident response reporting, where one timeline describes what happened, while another documents how it was discovered.

| Phase | Activity |
|--------|--------|
| T0 | Adversary executes WMIC remotely against target host |
| T1 | `net user /add` creates backdoor account `A1berto` |
| T2 | Windows writes registry keys under SAM hive |
| T3 | Impersonation pattern established via look-alike username |
| T4 | No authentication activity observed for backdoor account |
| T5 | Encoded PowerShell executes on separate host |
| T6 | Outbound HTTP communication to external PHP endpoint |

---

### 7) Indicators of Compromise (IOCs)

The indicators listed below represent high-confidence artifacts associated with account persistence, registry modification, remote execution, and command-and-control activity observed during this intrusion.

Field-level telemetry, log source mappings, and example detection logic derived from these indicators are documented separately in: `detection-artifact-report.md`

That report is intended for SOC analysts and detection engineers responsible for implementing monitoring and alerting controls.

<hr width="30%">

#### 7.1) Identity & Account IOCs

These indicators relate to unauthorized local account creation and potential impersonation of legitimate users. They are useful for identifying persistence mechanisms based on backdoor identities and for detecting masquerading techniques designed to blend into normal account activity.

- Backdoor account: `A1berto`
- Masqueraded legitimate account: `Alberto`

**Detection Use Cases:**
- Alert on new local account creation
- Detect look-alike usernames

<hr width="30%">

#### 7.2) Host-Based IOCs

These indicators identify specific endpoints involved in account creation, registry modification, and follow-on PowerShell activity. They support scoping of affected systems and correlation of multi-host behavior within the same intrusion sequence.

- Host with account creation and registry artifacts: `Micheal.Beaven`
- Host with PowerShell execution: `James.browne`

**Detection Use Cases:**
- Correlate suspicious activity across hosts
- Flag multi-host intrusion behavior

<hr width="30%">

#### 7.3) Command-Line IOCs

These indicators capture the exact commands and execution methods used to create the backdoor account and perform remote process execution. They are useful for detecting living-off-the-land abuse involving built-in Windows administrative utilities.

- `net user /add`
- `WMIC.exe process call create`

**Detection Use Cases:**
- Alert on account management commands executed remotely
- Monitor WMIC for process creation

<hr width="30%">

#### 7.4) Registry IOCs

These indicators reflect persistence-related artifacts written to the SAM registry hive as part of local account creation. They are useful for detecting long-lived identity persistence even when the backdoor account is not actively used for logon.

- `HKLM\SAM\SAM\Domains\Account\Users\Names\*`

**Detection Use Cases:**
- Monitor SAM hive modifications
- Correlate registry writes with account creation

<hr width="30%">

#### 7.5) PowerShell & Network IOCs

These indicators relate to encoded PowerShell execution and outbound web communication observed after account creation. They are useful for identifying post-compromise activity, secondary payload delivery, or command-and-control communication.

- Encoded PowerShell execution (`-enc`)
- Outbound destination: `hxxp[://]10[.]10[.]10[.]5/news[.]php`

**Detection Use Cases:**
- Alert on encoded PowerShell usage
- Block outbound connections to suspicious internal web servers

---

### 8) Case Determination

**Final Determination:**  
Confirmed Windows host compromise involving remote creation of a backdoor local account, registry persistence artifacts, impersonation through masquerading, and follow-on encoded PowerShell command execution contacting an external web endpoint.

Evidence supports a multi-stage intrusion using built-in administrative tools rather than malware-based persistence mechanisms.

---

### 9) Recommended Follow-Ups (Case Closure Actions)

The recommendations below summarize key containment, hardening, and detection priorities based on behaviors observed during this incident. Detailed technical controls, configuration guidance, and expanded monitoring strategies are documented separately in: `detection-and-hardening-recommendations.md`

This section highlights immediate and high-impact actions, while the supporting report provides implementation-level detail.

#### 9.1) Immediate Containment

- Disable and remove backdoor account `A1berto`
- Isolate affected hosts
- Block outbound communication to identified endpoint

<hr width="30%">  

#### 9.2) Hardening

- Restrict remote execution tooling
- Harden registry auditing for SAM hive
- Enforce identity governance controls

<hr width="30%">

#### 9.3) Detection

- Alert on local account creation events
- Detect WMIC remote process execution
- Monitor for encoded PowerShell activity

---

### 10) Supporting Reports (In This Folder)

The files below make up the full case package for this investigation and provide additional detail across analyst workflow, response actions, detection engineering, and executive-level reporting.

- `investigation-walkthrough.md` — Step-by-step analyst workflow, tool usage, screenshots, and investigative pivots
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

#### 11.1) Technique Mapping

- **Persistence — Create Account: Local Account (T1136.001)**
- **Defense Evasion — Masquerading (T1036)**
- **Execution / Lateral Movement — Windows Management Instrumentation (T1047)**
- **Persistence — Modify Registry (T1112)**
- **Execution — PowerShell (T1059.001)**
- **Command and Control — Application Layer Protocol: Web (T1071.001)**

<hr width="30%">

#### 11.2) MITRE ATT&CK Mapping (Table View)

| Tactic | Technique | Description |
|--------|----------|-------------|
| Persistence | **Create Account: Local Account (T1136.001)** | Backdoor account created using built-in utilities |
| Defense Evasion | **Masquerading (T1036)** | Look-alike username used to blend with legitimate users |
| Execution / Lateral Movement | **Windows Management Instrumentation (T1047)** | WMIC used for remote execution |
| Persistence | **Modify Registry (T1112)** | SAM hive modified to register local account |
| Execution | **PowerShell (T1059.001)** | Encoded PowerShell used for follow-on activity |
| Command and Control | **Application Layer Protocol: Web (T1071.001)** | Outbound web communication observed |

---


