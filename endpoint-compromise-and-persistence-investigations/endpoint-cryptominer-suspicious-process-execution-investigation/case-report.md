# Case Report — Endpoint Cryptominer Infection Investigation (Suspicious Process Execution and Resource Abuse)

**Case Type:** Endpoint Compromise / Unauthorized Software Execution  
**Primary Abuse Pattern:** User-launched cryptocurrency mining software executing from user-writable directory  
**Status:** Closed (investigation complete)  
**Confidence Level:** High — correlated SIEM alert, Windows process creation telemetry, and execution path analysis

---

### 1) Executive Summary

This case investigates a SIEM-generated alert triggered by suspicious process execution on a Windows endpoint. The executable `cudominer.exe` was identified as running under a standard user context and originating from a user-writable directory, behavior consistent with unauthorized cryptocurrency mining activity.

Correlation of SIEM alert metadata with Windows Security Event ID 4688 confirmed that the process was launched by the user account `Chris.Fort` on host `HR_02`. Review of the execution path and detection rule logic validated that the alert was functioning as designed and accurately detected malicious behavior. Based on these findings, the alert was classified as a true positive representing resource hijacking via cryptocurrency mining software.

Evidence supporting these conclusions includes:

- SIEM alert identifying anomalous executable name (see *Suspicious Process Identification*, Figure 1)
- Process creation events attributing execution to specific user and host (see *User and Host Attribution*, Figure 2)
- Execution from user-writable temporary directory rather than standard application paths
- SIEM correlation rule matching mining-related executable naming patterns (see *Detection Rule Review*, Figure 3)

---

### 2) Incident Background

The organization received an automated SIEM alert indicating suspicious process execution associated with potential cryptocurrency mining activity. Because mining malware often masquerades as legitimate executables and may be installed through social engineering or unauthorized downloads, the alert required validation to determine whether the behavior was benign or malicious.

The investigation focused on validating the alert by determining:

- Which executable triggered the detection
- Which user and host were responsible for execution
- Whether the execution context aligned with known malicious behaviors
- Whether the alert should be classified as a true positive or false positive

The objective was to confirm malicious activity and determine appropriate containment actions.

---

### 3) Scope

This section defines which endpoints, user accounts, and telemetry sources were included in validating the suspicious process execution alert, as well as what activity was not observed within the available dataset. Clearly defining scope helps distinguish confirmed host-level execution from broader compromise or lateral movement that was not supported by the evidence.

#### In-Scope

| Category | Included Items |
|--------|-----------------|
| **Affected Endpoint** | • HR_02 |
| **Associated User Account** | • Chris.Fort |
| **Primary Evidence Sources** | • SIEM alert metadata<br>• Windows Security Event Logs (Event ID 4688 — Process Creation) |
| **Behavioral Focus Areas** | • Executable name and location<br>• User execution context<br>• Detection rule validation |

#### Out-of-Scope / Not Observed

| Category | Not Included / Not Observed |
|--------|------------------------------|
| **Lateral Movement** | No evidence of movement to other systems |
| **Persistence Mechanisms** | No registry, scheduled task, service, or startup persistence observed |
| **Network Communication Analysis** | No network telemetry or outbound communication reviewed |
| **Additional Infected Hosts** | No indicators of compromise on other endpoints |

The investigation was limited to validating the triggering alert and confirming host-level malicious activity.

---

### 4) Environment

This investigation validated suspicious process execution using host-based telemetry on a Windows endpoint. No network telemetry or external infrastructure data was available. Conclusions are based on host execution behavior and file placement patterns.

| Category | Details |
|--------|--------|
| **Affected System (Victim) OS** | • Windows workstation |
| **Analyst VM OS** | • Windows-based analyst workstation used for event log analysis |
| **Platforms & Services** | • Windows local execution environment — reviewed process creation and file locations<br>• Event log analysis utilities — extracted and filtered process execution records |
| **Data Sources Reviewed** | • Windows Security Event Logs (Event ID 4688 — process creation)<br>• Local file system artifacts (executable paths and filenames)<br>• User session and host identity context |

---

### 5) Evidence Summary

This section summarizes the primary evidence used to reconstruct attacker behavior and support the final case determination. It focuses on how each data source contributed to understanding the incident rather than listing all raw log fields or detection logic.

Detailed event fields, log source mappings, and detection-relevant artifacts extracted from this investigation are documented separately in: `detection-artifact-report.md`

This separation reflects common SOC workflows, where incident narratives and detection engineering references are maintained as distinct artifacts.

<hr width="30%">

#### 5.1) Alert Trigger — Suspicious Executable Identification

The investigation began with review of the SIEM alert, which identified the executable `cudominer.exe` as anomalous. The name closely resembles known cryptocurrency mining tools and deviates from standard enterprise application naming conventions.

This initial alert established the executable as the primary artifact for investigation.  
(See *Suspicious Process Identification*, Figure 1)

<hr width="30%">

#### 5.2) Authentication & Execution Attribution

Correlated Windows process creation events revealed that `cudominer.exe` was launched:

- **User:** `Chris.Fort`
- **Host:** `HR_02`

This confirmed that the activity occurred under a standard user context rather than a system service account.  
(See *User and Host Attribution*, Figure 2)

User-based execution is common in commodity malware infections delivered via downloads or phishing.

<hr width="30%">

#### 5.3) Execution Path Analysis

Inspection of process metadata revealed the executable path:

`C:\Users\Chris.Fort\temp\cudominer.exe`

Execution from user-writable temporary directories is atypical for legitimate enterprise software and commonly associated with:

- Malware droppers
- Unauthorized software downloads
- Living-off-the-land execution chains

This execution location significantly increased confidence that the process was malicious rather than legitimate software.

<hr width="30%">

#### 5.4) Detection Logic Validation

##### 5.4.1 SIEM Rule Review

The SIEM correlation rule responsible for the alert monitors Windows process creation events and evaluates executable names for mining-related keywords, including variations of:

- `miner`
- `crypt`

The executable `cudominer.exe` matched the detection logic, confirming that the alert fired as intended rather than due to misconfiguration.  
(See *Detection Rule Review*, Figure 3)


##### 5.4.2 Alert Classification Decision

Because:

- The executable name aligns with known mining tools
- Execution occurred from a non-standard, user-writable directory
- Execution occurred under a standard user context

The alert was classified as a **true positive** representing unauthorized cryptocurrency mining activity on the endpoint.

---

### 6) Investigation Timeline (Condensed)

The timeline below reflects the **reconstructed sequence of attacker and host activity**, not the step-by-step actions taken by the analyst during investigation. Detailed analyst workflow and tool usage are documented separately in the investigation walkthrough: `investigation-walkthrough.md`

This distinction mirrors real-world incident response reporting, where one timeline describes **what happened**, while another documents **how it was discovered**.

| Phase | Activity |
|------|----------|
| T0 | Unauthorized mining executable placed on endpoint |
| T1 | User executes `cudominer.exe` from temporary directory |
| T2 | Windows generates process creation telemetry (Event ID 4688) |
| T3 | SIEM correlation rule triggers alert |
| T4 | Analyst validates alert and classifies as true positive |

---

### 7) Indicators of Compromise (IOCs)

The indicators listed below represent high-confidence artifacts suitable for threat hunting, alerting, and scoping of similar activity. These IOCs are presented at a conceptual and operational level to support rapid understanding of what to monitor.

Field-level telemetry, log source mappings, and example detection logic derived from these indicators are documented separately in: `detection-artifact-report.md`

That report is intended for SOC analysts and detection engineers responsible for implementing monitoring and alerting controls.

<hr width="30%">

#### 7.1) Host-Based IOCs

These indicators identify the specific endpoint where the suspicious executable was observed and are useful for scoping potential impact, validating whether activity is isolated, and correlating additional telemetry associated with the same host.

- Executable name: `cudominer.exe`
- Execution path: `C:\Users\Chris.Fort\temp\cudominer.exe`
- Host: `HR_02`

**Detection Use Cases:**
- Alert on executables launched from `%TEMP%` or `%APPDATA%`
- Monitor for miner-related executable names

<hr width="30%">

#### 7.2) User Attribution IOCs

These indicators relate to the user context under which the suspicious process was executed and are useful for identifying potential infection vectors such as unauthorized downloads, social engineering, or misuse of local execution privileges.

- User account: `Chris.Fort`

**Detection Use Cases:**
- Identify repeated suspicious executions tied to the same user
- Correlate abnormal processes with user download behavior

<hr width="30%">

#### 7.3) Behavioral IOCs

These indicators capture the executable name and file location associated with the suspicious process and are useful for detecting unauthorized software execution, especially when binaries originate from user-writable directories rather than standard application paths.

- Windows Security Event ID: `4688`
- Process name matching mining patterns
- Sustained resource utilization potential

**Detection Use Cases:**
- Correlate unknown executables with high CPU usage
- Alert on rare process names across endpoints

<hr width="30%">

#### 7.4) IOC Limitations

While the indicators above are high-confidence within the context of this alert, many can be easily modified by attackers, including executable names and file paths. As a result, detection strategies should prioritize behavioral correlations and execution context over static signatures alone.

- Executable names can be easily changed by attackers
- File paths may vary between infections
- Mining software may be packed or disguised

As a result, behavioral detection (execution from user-writable paths combined with anomalous process names) is more reliable than static signatures alone.

---

### 8) Case Determination

**Final Determination:**  
Confirmed unauthorized cryptocurrency mining software execution on corporate endpoint.

**Why false positive was ruled out:**

- Executable name matches known mining tools
- Execution occurred from user-writable directory
- No legitimate enterprise software uses this naming convention or path

This activity represents misuse of endpoint resources for attacker-controlled computation.

---

### 9) Recommended Follow-Ups (Case Closure Actions)

The recommendations below summarize key containment, hardening, and detection priorities based on behaviors observed during this incident. Detailed technical controls, configuration guidance, and expanded monitoring strategies are documented separately in the dedicated recommendations report: `detection-and-hardening-recommendations.md`

This section is intended to highlight immediate and high-impact actions, while the supporting report provides implementation-level detail for security engineering and operations teams.

<hr width="30%">

#### 9.1) Immediate Containment

- Isolate affected endpoint `HR_02`
- Terminate malicious process
- Remove unauthorized executable from disk
- Reset credentials for associated user account

<hr width="30%">

#### 9.2) Hardening

- Restrict execution from `%TEMP%` and `%APPDATA%`
- Implement application allowlisting
- Enforce endpoint protection policies

<hr width="30%">

#### 9.3) Detection

- Alert on execution from user-writable directories
- Monitor for miner-related process names
- Correlate unknown executables with CPU utilization anomalies

---

### 10) Supporting Reports (In This Folder)

Each investigation is documented using a standardized case package to separate analyst workflow, executive summaries, detection content, and response actions. The files below provide supporting detail and extended analysis beyond what is summarized in this case report.

- `investigation-walkthrough.md` — Step-by-step analyst workflow, tool usage, screenshots, and investigative pivots.
- `incident-summary.md` — Executive-level narrative summarizing what happened, business impact, and why it matters.
- `incident-response-report.md` — Containment, eradication, and recovery actions, along with response validation steps.
- `detection-artifact-report.md` — Log fields, detection logic, and SIEM-relevant artifacts derived from this incident.
- `detection-and-hardening-recommendations.md` — Preventive controls and monitoring improvements mapped to observed failures or gaps.
- `MITRE-ATTACK-mapping.md` — Detailed technique mapping with evidence references and defensive considerations.
- `images/` — All screenshots and visual evidence referenced throughout the investigation.
- `README.md` — High-level overview of the investigation, environment, and lab objectives.

---

### 11) MITRE ATT&CK Mapping

The mappings below provide a **high-level summary of confirmed adversary behaviors** observed during this incident and are intended as a quick reference for understanding the overall attack lifecycle.

- For full investigative context and evidence-backed technique justification, see: `investigation-walkthrough.md`
- For expanded MITRE technique analysis and detection considerations, see: `MITRE-ATTACK-mapping.md`

<hr width="30%">

### 11.1) Technique Mapping

- **Execution — User Execution (T1204):** Malicious executable launched by user.
- **Impact — Resource Hijacking (T1496):** Host resources consumed by mining activity.

<hr width="30%">

### 11.2 MITRE ATT&CK Mapping (Table View)

| Tactic | Technique | Description |
|--------|----------|-------------|
| Execution | **User Execution (T1204)** | User launched unauthorized executable triggering SIEM alert |
| Impact | **Resource Hijacking (T1496)** | Cryptocurrency mining consumed host resources |

---






