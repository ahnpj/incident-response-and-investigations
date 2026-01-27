# MITRE ATT&CK Mapping - Windows Malware Intrusion Lifecycle Investigation (Lateral Movement and Multi-Stage Host Compromise on Windows)

This document maps attacker behaviors observed during this investigation to MITRE ATT&CK tactics and techniques using direct evidence from firewall telemetry, OpenSSH Operational logs, Windows Security events, Sysmon file and registry telemetry, and timeline correlation performed during analysis.

All mappings are based on confirmed activity reconstructed during the investigation rather than inferred attacker intent or assumed tooling.

The purpose of this mapping is to support standardized incident classification, detection coverage validation, and alignment with adversary behavior frameworks commonly used by security operations teams.

---

### How This Mapping Was Performed

Techniques were mapped by reviewing:

- Firewall logs showing external reconnaissance behavior
- Local service exposure validation using PowerShell
- OpenSSH Operational authentication telemetry
- Windows Security events for account lifecycle activity
- Sysmon process creation and file creation events
- Sysmon registry value creation events
- Timeline correlation between access, malware staging, and persistence

Each technique below references specific investigative pivots and artifacts that supported classification.

---

### MITRE ATT&CK Mapping (Narrative View)

### (1) Reconnaissance

#### ▶ (1.1) Active Scanning (T1595)

**Observed Behavior:**  
Firewall logs show a single external source IP (`192.168.1.33`) sending TCP SYN-only probes to the same destination host (`192.168.1.43`) across multiple common service ports: 21, 22, 80, 443, 3389, and 445. No sessions were established and no data was transferred. The activity occurred prior to any authentication events or malware staging activity.

**Why This Maps to ATT&CK:**  
ATT&CK defines Active Scanning as probing of target systems to identify exposed services and access vectors prior to exploitation. Because this activity occurred externally and before access, it is classified as reconnaissance rather than post-compromise discovery.

#### Evidence Sources and Attribution:  
- FortiGate firewall logs showing repeated SYN packets  
- No completed TCP handshakes or payload transfer  
- Multiple unrelated service ports targeted in short time window


### (2) Initial Access

#### ▶ (2.1) External Remote Services (T1133)

**Observed Behavior:**  
Local enumeration using `netstat -an | findstr LISTENING` confirmed that port 22 (SSH) was actively listening on the endpoint, and reconnaissance activity specifically targeted this port. The attacker later authenticated over this service using valid credentials.

**Why This Maps to ATT&CK:**  
External Remote Services describes adversaries accessing systems through exposed services such as SSH, RDP, or VPN when those services are reachable from outside the network.

#### Evidence Sources and Attribution:  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Local Enumeration | PowerShell enumeration confirming SSH listening on port 22 | Confirms service availability on host |
| External Probing | External reconnaissance probing port 22 | Indicates attacker discovery of exposed service |
| Authentication Telemetry | Subsequent SSH authentication telemetry | Links probing to follow-on access attempts |


### (3) Credential Access

#### ▶ (3.1) Brute Force (T1110)

**Observed Behavior:**  
OpenSSH Operational logs show multiple failed password attempts for the `Administrator` account from `192.168.1.33`, followed by a successful authentication from the same source IP. This pattern indicates repeated credential attempts until a valid password was accepted.

**Why This Maps to ATT&CK:**  
Brute Force describes repeated authentication attempts against an account until valid credentials are discovered. The observed SSH log sequence directly supports this technique.

#### Evidence Sources and Attribution:  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| OpenSSH Logs | “Failed password for administrator from 192.168.1.33” | Indicates unsuccessful brute-force attempts |
| OpenSSH Logs | “Accepted password for administrator from 192.168.1.33” | Confirms successful authentication |
| Source Consistency | Same source IP and targeted account | Supports brute-force leading to compromise |


#### ▶ (3.2) Valid Accounts (T1078)

**Observed Behavior**  
After successful brute-force authentication, all subsequent attacker actions were performed under the context of legitimate user accounts, beginning with the built-in `Administrator` account and later using the attacker-created `sysadmin` account.

**Why This Maps to ATT&CK:**  
Valid Accounts applies when adversaries use legitimate credentials to operate on compromised systems, regardless of how those credentials were obtained.

#### Evidence Sources and Attribution:  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| SSH Authentication | Successful SSH login as `Administrator` | Confirms attacker access |
| Execution Context | System changes executed under authenticated user | Links actions to attacker session |
| Access Method | No exploit-based access observed | Supports credential-based compromise conclusion |


### (4) Persistence

#### ▶ (4.1)  Create Account: Local Account (T1136.001)

**Observed Behavior:**  
After gaining administrative access, the attacker created a new local user account named `sysadmin`, confirmed by Windows Security Event ID 4720. The account was later added to the local Administrators group.

**Why This Maps to ATT&CK:**  
Creating new local accounts is a common persistence mechanism that allows attackers to retain access even if original credentials are reset.

#### Evidence Sources and Attribution:  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Windows Security Logs | Event ID 4720 — user account created | Confirms new account creation |
| Account Name | `sysadmin` | Identifies attacker-created account |
| Temporal Correlation | Occurs after successful SSH authentication | Links account creation to intrusion |

#### ▶ (4.2)  Boot or Logon Autostart Execution (T1547) & Registry Run Keys / Startup Folder (T1547.001)

**Observed Behavior:** 
Sysmon Event ID 13 shows two registry autorun values created shortly after malware files were written to disk. These values cause automatic execution during user logon:

- `Windows Atapi x86_64 Driver` → `C:\Users\Administrator\AppData\Roaming\WPDNSE\svchost.exe`
- `Windows SCR Manager` → `C:\Users\Administrator\AppData\Roaming\WPDNSE\rundll33.exe`

These values cause automatic execution during user logon.

**Why This Maps to ATT&CK:**  
ATT&CK documents Run key modifications as a persistence technique that triggers malware execution at startup or logon without further attacker interaction.

#### Evidence Sources and Attribution:  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Sysmon Logs | Event ID 13 — registry value creation | Confirms persistence via registry |
| Time Window | Values created between 5:24 PM and 5:26 PM | Supports coordinated post-compromise activity |
| Registry Targets | Values point to malware-staged executables | Links persistence to malicious payloads |


### (5) Collection

#### ▶ (5.1) Input Capture: Keylogging (T1056.001)

**Observed Behavior:**  
Sysmon process creation logs show `7z.exe` executing the command: `7z e keylogger.rar`. Shortly after administrative access was obtained, indicating the attacker extracted a keylogging payload.

**Why This Maps to ATT&CK:**  
Keylogging is a defined sub-technique of Input Capture, used to collect credentials and sensitive user input after compromise.

#### Evidence Sources and Attribution:  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Sysmon Logs | Event ID 1 — process creation | Identifies execution of extraction tool |
| Extraction Tool | 7-Zip command observed | Confirms archive extraction activity |
| Archive Naming | Archive explicitly indicates keylogging functionality | Supports malicious payload classification |
| Timing Correlation | Occurred during post-compromise window | Links to attacker activity timeline |

#### ▶ (5.2) Data from Local System (T1005)

**Observed Behavior:**  
Multiple executables and supporting files were written to disk in the attacker-controlled directory: `C:\Users\Administrator\AppData\Roaming\WPDNSE\`, including: `svchost.exe`, `rundll33.exe`, and `atapi.sys`.

**Why This Maps to ATT&CK:**  
T1005 covers staging and accessing data on local systems, including preparation of malware components and collection infrastructure.

#### Evidence Sources and Attribution:  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Sysmon Logs | Event ID 11 — file creation | Confirms dropped payloads |
| Timestamp Alignment | Matches malware extraction timeframe | Correlates files to archive contents |

### (6) Defense Evasion

#### ▶ (6.1) Rootkit (T1014)

**Observed Behavior:**  
A file named `atapi.sys` was created in a user-writable roaming profile directory instead of a legitimate system driver path. The filename matches a legitimate Windows driver but is located in an abnormal directory.

**Why This Maps to ATT&CK:**  
Masquerading kernel-style components in non-standard locations aligns with rootkit-style evasion techniques described in ATT&CK.

#### Evidence Sources and Attribution:  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Sysmon Logs | Event ID 11 — file creation | Confirms file drop |
| File Name | `atapi.sys` | Identifies suspicious driver-style artifact |
| File Path | `C:\Users\Administrator\AppData\Roaming\WPDNSE\` | Indicates user-profile persistence location |

#### ▶ (6.2) Indicator Removal on Host (T1070)

**Observed Behavior**  
Windows Security Event ID 4726 confirms deletion of a local user account (`DRB`) after attacker persistence mechanisms were established.

**Why This Maps to ATT&CK:**  
Removing user accounts after compromise reduces visibility and complicates investigation, which qualifies as indicator removal behavior.

#### Evidence Sources and Attribution:  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Windows Security Logs | Event ID 4726 — user account deleted | Confirms account removal |
| Sequence | Occurred after creation and elevation of `sysadmin` | Indicates cleanup or cover-up behavior |

### (7) Impact

#### ▶ (7.1) Account Access Removal (T1531)

**Observed Behavior:**  
The attacker deleted a legitimate user account after securing persistent administrative access, disrupting normal system access and potentially hindering recovery.

**Why This Maps to ATT&CK:**  
ATT&CK classifies removal of legitimate account access as an impact technique when attacker actions disrupt system availability or user access.

#### Evidence Sources and Attribution:  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Windows Security Logs | Event ID 4726 — user account deleted | Confirms account removal |
| Deleted Account | `DRB` | Identifies affected user account |

---

### Techniques Considered but Not Observed

The following techniques were evaluated but not supported by available evidence:

- **Credential Dumping (T1003):** No LSASS access or memory dumping artifacts observed  
- **Exploitation for Privilege Escalation (T1068):** Privileges were obtained via group membership changes  
- **Lateral Movement Techniques:** No evidence of access to additional hosts

---

### MITRE ATT&CK Mapping (Table View)

This table provides a condensed reference suitable for reporting, detection validation, and technique tracking across multiple investigations.

| Tactic | Technique ID | Technique Name | Evidence Summary |
|--------|--------------|----------------|------------------|
| Reconnaissance | T1595 | Active Scanning | External SYN-only probes to ports 21, 22, 80, 443, 3389, 445 |
| Initial Access | T1133 | External Remote Services | SSH service exposed and used for remote access |
| Credential Access | T1110 | Brute Force | Failed SSH attempts followed by successful login |
| Credential Access | T1078 | Valid Accounts | Continued actions under legitimate user context |
| Persistence | T1136.001 | Create Local Account | New local admin account `sysadmin` created |
| Persistence | T1547 | Boot or Logon Autostart Execution | Malware configured to execute at logon |
| Persistence | T1547.001 | Registry Run Keys | Autorun values pointing to staged malware |
| Collection | T1056.001 | Input Capture: Keylogging | Extraction of `keylogger.rar` using 7-Zip |
| Collection | T1005 | Data from Local System | Malware components staged in roaming profile |
| Defense Evasion | T1014 | Rootkit | Masqueraded driver file in abnormal directory |
| Defense Evasion | T1070 | Indicator Removal on Host | User account deletion post-compromise |
| Impact | T1531 | Account Access Removal | Legitimate account removed after persistence |

---

### Detection and Control Relevance

This mapping highlights defensive monitoring opportunities including:

- Detection of external port scanning behavior
- Alerting on repeated SSH failures followed by success
- Monitoring local account creation and admin group changes
- Detecting file creation in user profile directories
- Alerting on autorun registry value creation

Associated detection logic and control recommendations are documented in:

- `detection-artifact-report.md`  
- `detection-and-hardening-recommendations.md`

---

###  Notes and Assumptions

- All techniques are mapped strictly to behaviors confirmed in logs and file system artifacts.
- No attribution to specific malware families or threat actors is made.
- Mapping focuses on host-level compromise and persistence mechanisms observed during the investigation.

This mapping reflects how ATT&CK is applied during full intrusion lifecycle investigations using correlated network and endpoint telemetry.




