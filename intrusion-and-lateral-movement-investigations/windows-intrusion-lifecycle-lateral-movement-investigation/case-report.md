# Case Report — Windows Malware Intrusion Lifecycle Investigation (Lateral Movement and Multi-Stage Host Compromise on Windows)

**Case Type:** Endpoint Compromise / Credential Abuse / Malware Deployment  
**Primary Abuse Pattern:** External service reconnaissance followed by brute-force SSH authentication, account manipulation for persistence, malware deployment, registry-based autorun persistence, and cleanup activity  
**Status:** Closed (investigation complete)  
**Confidence Level:** High — correlated firewall, OpenSSH, Windows Security, Sysmon, file system, and registry telemetry

---

## 1) Executive Summary

This case reconstructs a full malware intrusion lifecycle on a Windows endpoint, beginning with external reconnaissance and progressing through credential-based access, account manipulation, malware deployment, persistence establishment, and cleanup actions.

Firewall logs confirmed that the host was externally probed across multiple common service ports. Subsequent analysis validated that SSH was exposed and actively listening, and OpenSSH operational logs confirmed multiple failed authentication attempts followed by successful login to the built-in Administrator account from the same external source IP. After gaining access, the attacker created a new local administrative account, elevated its privileges, and deleted an existing user account, indicating both persistence and impact activity.

Post-compromise telemetry revealed extraction of a compressed malware archive, staging of multiple masquerading executables in a user-writable roaming directory, creation of a malicious driver file, and registry autorun modifications designed to ensure execution at logon. OSINT research further linked the malware artifacts to a publicly available GitHub keylogger project.

Correlated evidence across network, authentication, endpoint, file system, and registry telemetry supports classification of this incident as a full post-exploitation intrusion leveraging valid credentials and living-off-the-land execution rather than exploit-based delivery.

---

## 2) Incident Background

The investigation was initiated after abnormal firewall activity and endpoint behavior suggested unauthorized external interaction with a Windows host. Because multiple telemetry sources were available, the objective was to reconstruct attacker actions chronologically rather than validate a single alert.

The investigation focused on identifying:

- Whether reconnaissance occurred prior to access
- Which service was leveraged for initial access
- Whether credentials were abused rather than exploited
- Whether attacker-controlled persistence mechanisms were created
- Whether malware artifacts were introduced and executed
- Whether cleanup or impact actions occurred

Rather than performing exploit analysis or reverse engineering, the investigation prioritized defender-focused reconstruction of attacker tradecraft using available logs and host artifacts.

---

## 3) Scope

This section defines which systems, identities, and data sources were included in the investigation, as well as what activity was not observed within the available evidence. Clearly defining scope helps distinguish confirmed host-level compromise from assumptions about broader network intrusion that are not supported by telemetry.

### In-Scope

- **Affected host:** Single Windows endpoint
- **Primary evidence sources:**
  - FortiGate firewall logs
  - OpenSSH Operational logs
  - Windows Security Event Logs
  - Sysmon telemetry (process, file, registry)
  - File system artifacts
  - Registry modifications
- **Behavioral focus areas:**
  - External reconnaissance
  - Credential-based authentication abuse
  - Account creation and privilege escalation
  - Malware staging and execution
  - Registry-based persistence
  - Cleanup and access-disruption activity

### Out-of-Scope / Not Observed

- Lateral movement to additional hosts
- Network exfiltration beyond local staging
- Memory-only malware execution
- Kernel-level exploit validation

Conclusions are based solely on artifacts observable within the compromised endpoint and available network telemetry.

---

## 4) Environment

This investigation reconstructed a full intrusion lifecycle using perimeter, authentication, and endpoint telemetry.

**Affected System (Victim) Operating System:**
- Windows endpoint exposed to external network

**Analyst Virtual Machine Operating System:**
- Windows-based analyst workstation used for SIEM and log correlation

**Platforms and Services:**
- OpenSSH service — reviewed authentication attempts and login success
- Windows authentication services — analyzed account creation, deletion, and group changes
- Endpoint monitoring agents — provided process, file, and registry telemetry

**Data Sources Reviewed:**
- FortiGate firewall logs (external scanning activity)
- OpenSSH Operational logs (authentication attempts)
- Windows Security Event Logs
  - Account creation
  - Group membership changes
  - Account deletion
- Sysmon Operational Logs
  - Process creation
  - File creation
  - Registry modifications
- Local file system artifacts

**Analyst Note:**  
The investigation reflects post-incident reconstruction using stored telemetry rather than live response.

---

## 5) Evidence Summary

This section summarizes the primary evidence used to reconstruct reconnaissance, credential abuse, malware deployment, persistence establishment, and cleanup activity observed during this intrusion. It focuses on how each data source contributed to understanding attacker behavior and impact rather than listing raw log fields.

Detailed event records, registry paths, and detection-relevant artifacts extracted from this investigation are documented separately in: `detection-artifact-report.md`

This separation reflects common SOC workflows, where incident narratives and detection engineering references are maintained as distinct artifacts.


### 5.1 External Reconnaissance — Firewall Telemetry

Firewall logs showed repeated inbound TCP SYN-only probes from:

- **Source IP:** `192.168.1.33`
- **Target Host:** `192.168.1.43`

Targeted destination ports included:

- 21 (FTP)
- 22 (SSH)
- 80 (HTTP)
- 443 (HTTPS)
- 3389 (RDP)
- 445 (SMB)

Connections did not complete TCP handshakes and transferred no payload data, indicating service discovery rather than exploitation attempts. Repeated probing of multiple unrelated services strongly indicates reconnaissance activity.


### 5.2 Service Exposure Validation — Local Enumeration

Local enumeration confirmed that port 22 (SSH) was actively listening on the host, making it a viable initial access vector consistent with earlier reconnaissance activity.

The presence of SSH services on Windows is non-default and represents an increased attack surface when externally exposed.


### 5.3 Credential Abuse — OpenSSH Authentication Logs

OpenSSH Operational logs showed:

- Multiple failed authentication attempts for:
  - **Account:** `Administrator`
  - **Source IP:** `192.168.1.33`
- Followed by a successful authentication event for the same account and source

This pattern confirms brute-force authentication rather than exploit-based access and establishes the timestamp of first unauthorized access.


### 5.4 Account Persistence — Local User Creation

Windows Security Event ID `4720` confirmed creation of a new local user account:

- **Created account:** `sysadmin`

The account was created immediately after successful attacker authentication, confirming it was attacker-controlled and not part of routine provisioning.


### 5.5 Privilege Escalation — Administrator Group Membership

Windows Security Event ID `4732` confirmed that:

- `sysadmin` was added to the local **Administrators** group

This granted full administrative control and ensured persistent elevated access independent of the original compromised credentials.


### 5.6 Cleanup / Impact — Account Deletion

Windows Security Event ID `4726` confirmed deletion of a separate local user account:

- **Deleted account:** `DRB`

Deletion occurred after persistence was established, indicating cleanup or access-disruption behavior.


### 5.7 Malware Deployment — Archive Extraction

Sysmon Event ID `1` (Process Create) showed execution of:

- `C:\Program Files\7-Zip\7z.exe`
- Command line: `7z e keylogger.rar`

This confirms extraction of a compressed malware archive after administrative access was established.


### 5.8 Malware Artifacts — File Creation

Sysmon Event ID `11` (FileCreate) confirmed creation of:

- `svchost.exe`
- `rundll33.exe`
- `atapi.sys`

All files were written to:

- `C:\Users\Administrator\AppData\Roaming\WPDNSE\`

Use of legitimate system filenames in a user-writable directory strongly indicates masquerading behavior.


### 5.9 Persistence Establishment — Registry Autorun

Sysmon Event ID `13` (RegistryValueSet) confirmed creation of autorun registry values:

- **Value Name:** `Windows Atapi x86_64 Driver` → `svchost.exe`
- **Value Name:** `Windows SCR Manager` → `rundll33.exe`

These values ensured execution at logon, confirming registry-based persistence.


### 5.10 Malware Attribution — OSINT Correlation

Open-source research linked observed filenames, execution behavior, and persistence methods to a public GitHub keylogger project authored by:

- **GitHub User:** `ajayrandhawa`

While attribution does not identify the operator, it confirms commodity tooling rather than bespoke malware.

---

## 6) Investigation Timeline (Condensed)

The timeline below reflects reconstructed attacker and host activity, not analyst workflow. Detailed investigation steps and screenshots are documented separately in: `investigation-walkthrough.md`

| Phase | Activity |
|--------|--------|
| T0 | External TCP SYN scans across common service ports |
| T1 | SSH confirmed listening locally |
| T2 | Repeated failed SSH authentication attempts |
| T3 | Successful SSH login to Administrator |
| T4 | Creation of new local user account (`sysadmin`) |
| T5 | Account elevated to Administrators group |
| T6 | Separate user account deleted |
| T7 | Malware archive extracted |
| T8 | Masquerading executables and driver file created |
| T9 | Registry autorun persistence established |
| T10 | Malware attributed via OSINT |

---

## 7) Indicators of Compromise (IOCs)

The indicators listed below represent high-confidence artifacts associated with reconnaissance, credential abuse, malware staging, persistence, and cleanup activity observed during this intrusion.

Field-level telemetry and detection pivots are documented separately in: `detection-artifact-report.md`


### 7.1 Network & Reconnaissance IOCs

These indicators reflect pre-compromise service discovery behavior.

- Scanning source IP: `192.168.1.33`
- Target host IP: `192.168.1.43`
- Probed ports: `21, 22, 80, 443, 3389, 445`

**Detection Use Cases:**
- Alert on multi-port SYN scanning
- Correlate scans followed by authentication attempts


### 7.2 Identity & Authentication IOCs

These indicators reflect credential abuse and persistence via account manipulation.

- Compromised account: `Administrator`
- Attacker-created account: `sysadmin`
- Deleted account: `DRB`

**Detection Use Cases:**
- Detect repeated authentication failures followed by success
- Alert on local account creation and admin group changes


### 7.3 Malware & File System IOCs

These indicators reflect staged malware artifacts.

- Archive: `keylogger.rar`
- Executables: `svchost.exe`, `rundll33.exe`
- Driver: `atapi.sys`
- Directory: `C:\Users\Administrator\AppData\Roaming\WPDNSE\`

**Detection Use Cases:**
- Alert on executables in roaming profile directories
- Detect masquerading system filenames outside system paths


### 7.4 Registry Persistence IOCs

These indicators reflect autorun persistence configuration.

- Registry values:
  - `Windows Atapi x86_64 Driver`
  - `Windows SCR Manager`

**Detection Use Cases:**
- Monitor new Run key values
- Correlate registry changes with file creation events


### 7.5 IOC Limitations

While the indicators above are high-confidence within this investigation, attackers can change IP addresses, filenames, account names, and registry value labels. Detection strategies should prioritize behavioral correlations such as scanning followed by authentication, account creation after access, and registry autoruns following file staging rather than relying on static indicators alone.

---

## 8) Case Determination

**Final Determination:**  
Confirmed Windows host compromise involving credential-based access via exposed SSH service, followed by account manipulation for persistence, malware deployment, registry-based autorun persistence, and cleanup actions.

Evidence supports a full post-exploitation intrusion leveraging valid credentials and commodity malware rather than vulnerability exploitation or user-driven malware execution.

---

## 9) Recommended Follow-Ups (Case Closure Actions)

The recommendations below summarize key containment, hardening, and detection priorities based on behaviors observed during this incident. Detailed technical controls are documented separately in: `detection-and-hardening-recommendations.md`

### Immediate Containment

- Disable or restrict external SSH access
- Reset compromised credentials
- Remove unauthorized local accounts
- Isolate affected host

### Hardening

- Enforce strong password policies and lockout thresholds
- Implement MFA for remote administration
- Restrict execution from user-writable directories
- Harden registry autorun locations

### Detection

- Alert on external scanning behavior
- Monitor SSH brute-force attempts
- Detect local account lifecycle events
- Alert on registry Run key creation

---

## 10) Supporting Reports (In This Folder)

The files below make up the full case package for this investigation and provide additional detail across analyst workflow, response actions, detection engineering, and executive-level reporting.

- `investigation-walkthrough.md` — Step-by-step analyst workflow and screenshots  
- `incident-summary.md` — Executive-level narrative and business impact  
- `incident-response-report.md` — Containment and recovery actions  
- `detection-artifact-report.md` — Detection-relevant artifacts and telemetry  
- `detection-and-hardening-recommendations.md` — Preventive controls and monitoring improvements  
- `MITRE-ATTACK-mapping.md` — Detailed technique mapping with evidence references  
- `images/` — Screenshots and visual evidence  
- `README.md` — High-level investigation overview

---

## 11) MITRE ATT&CK Mapping

The mappings below provide a high-level summary of confirmed adversary behaviors observed during this incident.

- Full investigative context and evidence references: `investigation-walkthrough.md`  
- Expanded technique analysis and detection considerations: `MITRE-ATTACK-mapping.md`

### Technique Mapping

- **Reconnaissance — Active Scanning (T1595)**
- **Initial Access — External Remote Services (T1133)**
- **Credential Access — Brute Force (T1110)**
- **Credential Access — Valid Accounts (T1078)**
- **Persistence — Create Account (T1136)**
- **Persistence — Boot or Logon Autostart Execution (T1547)**
- **Persistence — Registry Run Keys / Startup Folder (T1547.001)**
- **Collection — Input Capture: Keylogging (T1056.001)**
- **Collection — Data from Local System (T1005)**
- **Defense Evasion — Rootkit (T1014)**
- **Defense Evasion — Indicator Removal on Host (T1070)**
- **Impact — Account Access Removal (T1531)**

### MITRE ATT&CK Mapping (Table View)

| Tactic | Technique | Description |
|------|-----------|-------------|
| Reconnaissance | **Active Scanning (T1595)** | External SYN probes across multiple service ports prior to compromise. |
| Initial Access | **External Remote Services (T1133)** | SSH service exposed and used for remote authentication. |
| Credential Access | **Brute Force (T1110)** | Repeated failed SSH logins followed by successful authentication. |
| Credential Access | **Valid Accounts (T1078)** | Post-access activity performed using legitimate account context. |
| Persistence | **Create Account: Local Account (T1136.001)** | New administrative account created to maintain access. |
| Persistence | **Boot or Logon Autostart Execution (T1547)** | Malware configured to execute automatically at logon. |
| Persistence | **Registry Run Keys / Startup Folder (T1547.001)** | Autorun registry values point to attacker-controlled executables. |
| Collection | **Input Capture: Keylogging (T1056.001)** | Keylogger archive deployed post-compromise. |
| Collection | **Data from Local System (T1005)** | Malware staged multiple local artifacts on disk. |
| Defense Evasion | **Rootkit (T1014)** | Driver file masqueraded as legitimate system component. |
| Defense Evasion | **Indicator Removal on Host (T1070)** | User account deleted after persistence established. |
| Impact | **Account Access Removal (T1531)** | Legitimate user account removed to disrupt access. |

---
