# Detection Artifact Report — Web Server Defacement Investigation (Malicious File Upload Exploitation and Web Shell Deployment)

### 1) Purpose and Scope
This report documents **network, web application, IDS, and host-based artifacts** observed during the investigation of a Joomla-based web server compromise that resulted in public website defacement. The purpose of this report is to provide **detection-relevant, evidence-backed indicators** that can be used for SOC alerting, threat hunting, and correlation engineering.

All artifacts in this report are derived from evidence and pivots documented in:

- `web-server-defacement-incident-investigation.md` — Splunk queries, log pivots, and analyst validation workflow  
- `case-report.md` — reconstructed attacker timeline and impact validation  
- `MITRE-ATT&CK-mapping.md` — technique and tactic classification  

This report complements:

- `incident-response-report.md` — response sequencing and remediation rationale  
- `detection-and-hardening-recommendations.md` — preventive and long-term security controls  

---

### 2) Environment and Log Sources

This section summarizes the telemetry sources used to identify and validate attack artifacts.

#### ▶ 2.1) Primary log sources used in the investigation

- **Suricata IDS (`suricata`)** — exploit signatures, scanner detection, malformed HTTP indicators  
- **HTTP stream logs (`stream:http`)** — request methods, URIs, POST body form data, and authentication attempts  
- **Firewall / UTM telemetry (`fortigate_utm`)** — outbound traffic, external communications, and reputation context  
- **Host telemetry (Sysmon)** — process creation and file execution validation on the web server  

#### ▶ 2.2) Confirmed assets

- **Victim host:** `192.168.250.70`  
- **Domain:** `imreallynotbatman.com`  
- **CMS:** Joomla  
- **Administrative endpoint:** `/joomla/administrator/index.php`  

---

### 3) High-Confidence Attack Sequence Anchors

This section lists **confirmed timeline anchors** that structured the investigation and were used to correlate artifacts across log sources.

| Anchor | Description | Evidence Source | Investigation Pivot |
|--------|------------|-----------------|---------------------|
| Scanner detection | Automated vulnerability scanning | Suricata IDS | Triggered initial triage |
| Admin endpoint targeting | Requests to Joomla admin login | HTTP logs | Led to credential analysis |
| Credential brute force | Repeated POST login attempts | HTTP logs | Identified password attack |
| Successful login | Valid credentials accepted | HTTP logs | Escalated to compromise |
| Malware upload | Executable written to server | HTTP + Sysmon | Confirmed host-level impact |
| Malware execution | Uploaded binary executed | Sysmon | Validated exploitation |
| External comms | Outbound traffic to attacker infra | Firewall | Confirmed active compromise |
| Defacement | Web content modified | HTTP logs | Confirmed business impact |

These anchors form the basis for multi-stage correlation detection strategies.

---

### 4) IDS Artifacts — Reconnaissance and Exploit Probing

This section documents intrusion detection alerts that identified early-stage attacker activity.

#### ▶ 4.1) Artifact: Acunetix Scanner Signatures

**Observed behavior:**  
Suricata generated alerts indicating patterns consistent with the Acunetix vulnerability scanner.

**Where identified:**  
Detected in Suricata logs during early investigation phases prior to credential abuse activity.

**Behavioral significance:**

- Indicates automated vulnerability assessment
- Common precursor to credential brute force or exploit attempts

**Detection guidance:**

- Alert on known scanner signatures targeting web servers
- Escalate severity when followed by authentication attempts or file uploads


#### ▶ 4.2) Artifact: Malformed HTTP Headers and Exploit Probes

**Observed behavior:**

- Requests containing unusual or malformed HTTP headers
- Payloads attempting to trigger application-level vulnerabilities

**Where identified:**  
Captured in Suricata IDS logs and cross-referenced with HTTP stream data.

**Behavioral significance:**

- Indicates probing for known vulnerabilities
- Suggests automated exploit frameworks

**Detection guidance:**

- Monitor repeated malformed requests from same source IP
- Correlate with later POST authentication attempts

---

### 5) Web Application Artifacts — Credential Abuse

This section documents application-layer indicators confirming credential brute-force and successful authentication.

#### ▶ 5.1) Artifact: Repeated POST Requests to Joomla Admin Login

**Observed behavior:**

- Multiple POST requests to:
  - `/joomla/administrator/index.php`
- Form fields containing varying username/password values

**Where identified:**  
HTTP stream logs were queried to extract POST body parameters during login attempts.

**Behavioral significance:**

- Confirms credential brute-force attack against CMS admin interface
- Indicates attacker intent to obtain authenticated access rather than exploit vulnerability

**Detection guidance:**

- Alert on:
  - excessive POST attempts to admin endpoints
- Apply thresholds by:
  - source IP
  - target account

#### ▶ 5.2) Artifact: Successful Administrative Authentication

**Observed behavior:**

- Login accepted using credentials:
  - `admin:batman`

**Where identified:**  
Confirmed via HTTP response codes and session continuation following login.

**Behavioral significance:**

- Marks transition from attack attempt to confirmed compromise
- Enables privileged CMS functionality including file uploads

**Detection guidance:**

- Alert on admin logins from:
  - unusual IPs
  - locations previously associated with scanning activity

---

### 6) Host-Based Artifacts — Malware Upload and Execution

This section documents host telemetry confirming attacker-controlled code execution.

#### ▶ 6.1) Artifact: Creation of Uploaded Executable

**Observed artifact:**

- Executable file created on web server:
  - `3791.exe`

**Where identified:**

- Correlated HTTP upload activity with Sysmon file creation events

**Behavioral significance:**

- Confirms attacker leveraged CMS functionality to place executable payload
- Indicates shift from application compromise to host compromise

**Detection guidance:**

- Alert when:
  - `.exe` files are created in web directories
- Correlate with:
  - authenticated CMS sessions

#### ▶ 6.2) Artifact: Execution of Uploaded Malware

**Observed artifact:**

- Sysmon ProcessCreate event showing execution of `3791.exe`

**Where identified:**  
Detected shortly after file upload confirmation.

**Behavioral significance:**

- Confirms attacker gained code execution on server
- Enables further exploitation and persistence

**Detection guidance:**

- Alert when:
  - web-uploaded files are executed
- Combine with:
  - web authentication telemetry

---

### 7) Network Artifacts — Outbound Communication

This section documents evidence of post-exploitation network activity.

#### ▶ 7.1) Artifact: Outbound Connections to Attacker Infrastructure

**Observed behavior:**

- Web server initiating outbound traffic to external IPs associated with defacement content

**Where identified:**  
Firewall and UTM logs showed outbound connections following malware execution.

**Behavioral significance:**

- Indicates command-and-control or resource retrieval
- Confirms server actively participating in attacker workflow

**Detection guidance:**

- Alert on:
  - unexpected outbound connections from web servers
- Enforce:
  - egress filtering policies

---

### 8) Defacement Artifacts — Content Modification

This section documents indicators confirming business impact.

#### ▶ 8.1) Artifact: External Resource Injection in Web Pages

**Observed behavior:**

- Web pages loading images from attacker-controlled domains

**Where identified:**  
HTTP logs showed outbound GET requests for defacement images during page loads.

**Behavioral significance:**

- Confirms attacker modified site content or templates
- Indicates public defacement rather than isolated compromise

**Detection guidance:**

- Monitor for:
  - changes in page content loading external resources
- Implement:
  - file integrity monitoring on web directories

---

### 9) Cross-Source Correlation Opportunities

This section outlines correlation strategies that reflect how compromise was confirmed during investigation.

#### ▶ 9.1) Correlation 1: IDS Scan → CMS Login Abuse

**Signals:**

- Scanner alerts from Suricata
- POST requests to admin endpoints from same IP

**Use case:**  
Detect transition from recon to active exploitation attempts.


#### ▶ 9.2) Correlation 2: Successful CMS Login → File Upload → Malware Execution

**Signals:**

- Admin login accepted
- Executable created in web directory
- Sysmon execution event

**Use case:**  
High-confidence confirmation of web-to-host compromise.


#### ▶ 9.3) Correlation 3: Malware Execution → Outbound Traffic

**Signals:**

- Sysmon process creation
- Firewall outbound sessions

**Use case:**  
Identify active post-exploitation behavior.

---

### 10) Indicator Reliability Considerations

This section distinguishes stable behavioral signals from easily changed indicators.

**Low reliability (easily modified):**

- File names (`3791.exe`)
- Specific image URLs used in defacement

**Higher reliability (preferred):**

- Sequence of CMS authentication → file upload → execution
- Outbound traffic from normally passive web servers
- IDS scanner signatures combined with authentication abuse

Behavior-based detection reduces evasion risk.

---

### 11) Closing Summary

This investigation demonstrated a full compromise chain:

- Automated scanning and probing  
- CMS credential brute force  
- Successful administrative login  
- Malware upload and execution  
- Outbound communication to attacker infrastructure  
- Public-facing defacement  

Each stage produced distinct artifacts across IDS, HTTP logs, firewall telemetry, and host sensors. Reliable detection requires **cross-domain correlation**, not isolated alerts.

Implementing multi-stage detection logic aligned with this sequence would allow defenders to detect and contain similar intrusions before public defacement or further exploitation occurs.

