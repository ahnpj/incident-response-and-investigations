# MITRE ATT&CK Mapping - Web Server Defacement Investigation (Malicious File Upload Exploitation and Web Shell Deployment)

This document maps attacker behaviors observed during this investigation to MITRE ATT&CK tactics and techniques using direct evidence from correlated web server logs, IDS alerts, firewall telemetry, and host-based process execution data.

All mappings are based on confirmed activity reconstructed during analysis rather than inferred attacker intent or assumed tooling.

The purpose of this mapping is to support standardized incident classification, detection coverage validation, and alignment with threat modeling frameworks commonly used by security operations teams.

---

### How This Mapping Was Performed

Techniques were mapped by reviewing:

- HTTP access logs and POST request parameters
- Suricata IDS alerts associated with exploit attempts
- Firewall logs confirming inbound and outbound sessions
- Host telemetry confirming file execution
- Timeline correlation between scanning, exploitation, execution, and defacement

Each technique below references the investigative pivots and artifacts that supported classification.

---

### MITRE ATT&CK Mapping (Narrative View)

### (1) Reconnaissance

#### ▶ (1.1) Active Scanning (T1595)

**Observed Behavior:**  
An external IP address generated a high volume of HTTP requests targeting CMS-related paths and triggered multiple IDS signatures associated with vulnerability discovery and malformed requests. Requests included enumeration of administrative paths and plugin endpoints commonly associated with Joomla installations.

**Why This Maps to ATT&CK:**  
Active scanning includes probing of external systems to identify vulnerabilities and exposed services prior to exploitation, which aligns with the observed automated discovery behavior.

**Evidence Sources and Attribution:**  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| IDS Alerts | Suricata alerts containing exploit and malformed header signatures | Indicates automated exploitation attempts |
| Target Paths | HTTP GET requests to CMS-specific paths such as `/joomla/administrator/` | Confirms probing for known CMS platforms |
| User-Agent | User-Agent indicating automated scanning activity (e.g., Acunetix scanner) | Identifies use of automated vulnerability scanner |
| Source IP | Repeated requests from a consistent external source IP | Links scanning activity to single attacker origin |


### (2) Initial Access

#### ▶ (2.1) Exploit Public-Facing Application (T1190)

**Observed Behavior:**  
After reconnaissance, the attacker targeted the web application’s administrative functionality and gained the ability to authenticate and upload files to the server. Follow-on activity included authenticated requests and file upload actions that required application-level access rather than network-layer compromise.

**Why This Maps to ATT&CK:**  
T1190 covers exploitation of vulnerabilities or weaknesses in externally accessible applications to gain access or code execution, which matches the observed access path.

**Evidence Sources and Attribution:**  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Request Method | HTTP POST requests to CMS administrative endpoints | Indicates attempts to interact with protected functionality |
| IDS Alerts | Alerts associated with application exploitation patterns | Confirms exploit-focused activity |
| Activity Shift | Transition from unauthenticated scanning to authenticated actions | Shows progression in attacker behavior |

### (3) Credential Access

#### ▶ (3.1) Brute Force (T1110)

**Observed Behavior:**  
Multiple authentication attempts were observed against the CMS administrative login page, with repeated POST requests containing different credential combinations. Analysis of POST body parameters revealed trial-and-error attempts prior to successful authentication.

**Why This Maps to ATT&CK:**  
Brute force includes repeated attempts to guess valid credentials through authentication mechanisms, which directly matches the observed login behavior.

**Evidence Sources and Attribution:**   
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Request Method | HTTP POST requests to CMS administrative endpoints | Indicates attempts to interact with protected functionality |
| IDS Alerts | Alerts associated with application exploitation patterns | Confirms exploit-focused activity |
| Activity Shift | Transition from unauthenticated scanning to authenticated actions | Shows progression in attacker behavior |


### (4) Initial Access / Persistence

#### ▶ (4.1) Valid Accounts (T1078)

**Observed Behavior:**  
Once valid credentials were obtained, the attacker authenticated using legitimate account access and continued performing privileged administrative actions within the CMS. This access enabled file upload, content modification, and backend configuration changes.

**Why This Maps to ATT&CK:**  
Use of compromised legitimate credentials to maintain access aligns with the Valid Accounts technique.

**Evidence Sources and Attribution:**   
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Successful Login | Successful authentication events using recovered credentials | Confirms attacker gained valid access |
| Admin Actions | Authenticated CMS administrative actions following login | Demonstrates post-auth access usage |
| Failure Absence | No further authentication failures during post-compromise phase | Supports possession of valid credentials |


### (5) Execution

#### ▶ (5.1) Command and Scripting Interpreter (T1059)

**Observed Behavior:**  
A Windows executable (`3791.exe`) was uploaded to the web server and executed, confirmed through host-based process creation telemetry. Execution occurred shortly after file upload, indicating attacker-controlled code was launched on the system.

**Why This Maps to ATT&CK:**  
Execution of attacker-controlled binaries or scripts using system interpreters or direct execution is covered under T1059 execution techniques.

**Evidence Sources and Attribution:**   
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Upload Method | HTTP multipart upload containing `3791.exe` | Confirms file delivery via web application |
| Process Execution | Sysmon process creation event referencing `3791.exe` | Confirms execution of uploaded payload |
| Timing Correlation | Timestamp correlation between upload and execution | Links web exploit to host compromise |


### (6) Command and Control

#### ▶ (6.1) Application Layer Protocol: Web (T1071.001)

**Observed Behavior:**  
After execution, the compromised host initiated outbound HTTP connections to attacker-controlled infrastructure on a non-standard port. The server repeatedly requested remote resources hosted on the attacker domain.

**Why This Maps to ATT&CK:**  
Use of standard web protocols for command-and-control or remote resource retrieval is explicitly covered under Application Layer Protocol techniques.

**Evidence Sources and Attribution:**  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Firewall Logs | Outbound connections to external host and port | Indicates external communication |
| IDS Alerts | Alerts on outbound HTTP sessions | Confirms application-layer outbound traffic |
| Payload Retrieval | Requests retrieving remote image payload used in defacement | Links outbound traffic to attack objective |


### (7) Impact

#### ▶ (7.1) Defacement (T1491)

**Observed Behavior:**  
The website homepage was modified to display attacker-controlled content by referencing a remotely hosted image. Visitors to the site observed replacement content rather than the original web page.

**Why This Maps to ATT&CK:**  
Modification of public-facing resources to display attacker content aligns directly with the Defacement impact technique.

**Evidence Sources and Attribution:**  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| HTTP Requests | Requests for attacker-hosted image | Confirms content delivery from attacker source |
| Web Rendering | Web content showing replaced homepage | Validates visible defacement impact |
| Activity Correlation | Correlation between outbound C2 traffic and visible defacement | Links attacker communication to site modification |

---

### MITRE ATT&CK Mapping (Table View)

| Tactic | Technique ID | Technique Name | Evidence Summary | Evidence Source |
|--------|--------------|----------------|------------------|-----------------|
| Reconnaissance | T1595 | Active Scanning | Automated CMS path enumeration and IDS exploit probes | IDS + HTTP logs |
| Initial Access | T1190 | Exploit Public-Facing Application | Application-level access leading to file upload | HTTP POST + IDS |
| Credential Access | T1110 | Brute Force | Repeated login attempts prior to successful auth | POST form data |
| Initial Access / Persistence | T1078 | Valid Accounts | Continued CMS access using valid credentials | Auth logs |
| Execution | T1059 | Command and Scripting Interpreter | Uploaded executable run on host (`3791.exe`) | Sysmon process logs |
| Command and Control | T1071.001 | Application Layer Protocol: Web | Outbound HTTP to attacker infrastructure | Firewall + IDS |
| Impact | T1491 | Defacement | Homepage modified to display attacker content | Web content + HTTP |

This table provides a condensed reference suitable for reporting, detection validation, and technique tracking across multiple investigations.

---

### Detection and Control Relevance

Mapping behaviors to MITRE ATT&CK supports defensive operations by:

- Highlighting detection opportunities for automated scanning and exploit attempts
- Supporting alerting on repeated CMS authentication failures
- Monitoring file uploads and executable creation in web directories
- Correlating web activity with host-based execution events
- Alerting on outbound connections from servers to unknown external hosts

Detection opportunities and preventive control recommendations associated with these techniques are documented in:

- `detection-artifact-report.md`  
- `detection-and-hardening-recommendations.md`

---

### Notes and Assumptions

- Techniques are mapped solely based on behaviors confirmed in available telemetry.
- No lateral movement beyond the web server host was observed within scope.
- Mapping avoids attribution to specific malware families or threat actor groups.

This mapping reflects how ATT&CK is commonly applied during web server compromise and defacement investigations involving application exploitation and post-exploitation activity.



