# Case Report — Web Server Defacement Investigation (Malicious File Upload Exploitation and Web Shell Deployment)

**Case Type:** Web Application Compromise / Malware Infection / Website Defacement  
**Primary Abuse Pattern:** Automated vulnerability scanning and credential brute force against Joomla admin interface, followed by malicious file upload, malware execution, outbound C2 communication, and website defacement via externally hosted image retrieval  
**Status:** Closed (investigation complete)  
**Confidence Level:** High — correlated HTTP, IDS, firewall, and host telemetry across the full intrusion lifecycle

---

### 1) Executive Summary

This case investigates a multi-stage web server compromise that resulted in the public defacement of the domain `imreallynotbatman.com`, hosted by Wayne Enterprises. Correlated network, application, IDS, and host telemetry demonstrates a complete attack chain beginning with automated vulnerability scanning, followed by credential brute force, authenticated access to the Joomla administrative interface, malware upload and execution, outbound communication to attacker-controlled infrastructure, and final defacement of public-facing content.

Suricata IDS and HTTP telemetry identified reconnaissance activity using the Acunetix vulnerability scanner, including malformed HTTP headers and exploit probes such as Shellshock (CVE-2014-6271). Subsequent HTTP POST activity to `/joomla/administrator/index.php` revealed brute-force credential attempts and eventual successful authentication using valid administrator credentials. After access was obtained, an executable payload (`3791.exe`) was uploaded to the server and executed, as confirmed by Sysmon process creation logs.

Outbound network telemetry then showed the compromised server initiating connections to attacker infrastructure, including retrieval of a defacement image (`poisonivy-is-coming-for-you-batman.jpeg`) hosted on an external domain. This behavior confirms that the attacker modified site content or templates to force outbound retrieval of defacement material, completing the attacker’s objective of public website defacement.

---

### 2) Incident Background

The investigation was initiated after confirmation that the public website `imreallynotbatman.com` had been visually defaced. Because multiple telemetry sources were available in the environment, the investigative objective was to reconstruct the full intrusion lifecycle rather than validate a single detection alert.

The investigation focused on identifying:

- Whether reconnaissance and vulnerability scanning occurred
- How initial access to the web application was achieved
- Whether credential abuse occurred rather than software exploitation
- Whether malware was uploaded and executed on the host
- Whether command-and-control communication was established
- How the defacement was delivered and persisted

The analysis prioritized defender-focused reconstruction using correlated log sources rather than exploit development or malware reverse engineering.

---

### 3) Scope

This section defines which systems, identities, and data sources were included in the investigation, as well as what activity was not observed within the available evidence. Clearly defining scope helps distinguish confirmed web application compromise from assumptions about broader infrastructure compromise that are not supported by telemetry.

#### ▶ 3.1) In-Scope

| Category | Included Items |
|--------|----------------|
| **Affected System** | • Web server hosting `imreallynotbatman.com` |
| **Server IP** | • `192.168.250.70` |
| **Primary Evidence Sources** | • Network, application, IDS, and host telemetry |
| **Behavioral Focus Areas** | • Web vulnerability scanning<br>• Credential brute force<br>• Authenticated admin access<br>• Malware upload and execution<br>• Outbound communication<br>• Defacement delivery |

#### ▶ 3.2) Out-of-Scope / Not Observed

- Lateral movement to other hosts
- Database compromise
- Privilege escalation beyond web server context
- Infrastructure-wide persistence mechanisms

Analysis was limited to telemetry associated with the compromised web server and attacker-controlled infrastructure observed during this incident.

---

### 4) Environment

This investigation reconstructed a full web server compromise using network, application, and host telemetry associated with a public-facing CMS environment.

#### ▶ 4.1) **Affected System (Victim) Operating System:**
- Linux-based web server hosting Joomla CMS

#### ▶ 4.2) **Analyst Virtual Machine Operating System:**
- Windows-based analyst workstation running centralized log analysis tools

#### ▶ 4.3) **Platforms and Services:**
- Joomla Content Management System (CMS) — reviewed administrative authentication and file upload activity
- Web server application stack — analyzed HTTP request handling and response behavior
- Centralized SIEM platform — correlated HTTP, IDS, firewall, and host telemetry

#### ▶ 4.4) **Data Sources Reviewed:**
- `stream:http` — HTTP flows, headers, form data, User-Agent, and URIs
- `suricata` — IDS exploit signatures and vulnerability scanning indicators
- `fortigate_utm` — firewall and web filtering telemetry
- `iis` — web access logs where present in dataset
- `XmlWinEventLog:Microsoft-Windows-Sysmon` — process execution and outbound network artifacts
- OSINT enrichment — VirusTotal, ThreatMiner, Hybrid Analysis (as referenced in investigation)

**Analyst Note:**  
Telemetry allowed reconstruction of attacker behavior across reconnaissance, authentication abuse, malware delivery, command-and-control activity, and defacement stages.

---

### 5) Evidence Summary

This section summarizes the primary evidence used to reconstruct reconnaissance, credential abuse, malware delivery, command-and-control communication, and defacement activity observed during this intrusion. It focuses on how each data source contributed to understanding attacker behavior and impact rather than listing raw log fields.

Detailed field-level artifacts, extracted credentials, file hashes, and detection pivots are documented separately in: `detection-artifact-report.md`


#### ▶ 5.1) Reconnaissance — Automated Vulnerability Scanning

Suricata IDS logs and HTTP telemetry identified large volumes of requests from:

- **Primary scanning IP:** `40.80.148.42`

Triggered IDS signatures included:

- SQL injection probes
- Cross-site scripting attempts
- XXE probes
- Shellshock exploit signatures (CVE-2014-6271)

HTTP headers included malformed or empty Host values and User-Agent strings associated with the Acunetix vulnerability scanner, confirming automated reconnaissance and vulnerability testing against the Joomla-based web server.


#### ▶ 5.2) Web Application Targeting — Joomla Admin Interface

HTTP logs revealed repeated access to:

- `/joomla/administrator/index.php`

Requests were primarily POST-based, consistent with authentication attempts against the Joomla administrative login interface. Targeting of CMS-specific administrative paths confirms attacker intent to gain authenticated control of the application rather than exploit unauthenticated vulnerabilities alone.


#### ▶ 5.3) Credential Brute Force — Authentication Abuse

Form submission data (`form_data`) extracted from HTTP POST events revealed repeated credential attempts originating primarily from:

- **Brute-force IP:** `23.22.63.114`

Submitted usernames and passwords were extracted using regex and URL decoding, confirming repeated authentication attempts. Eventually, successful authentication occurred from:

- **Successful login IP:** `40.80.148.42`
- **Credentials:** `admin : batman`

This pattern confirms coordinated scanning followed by credential abuse rather than vulnerability exploitation.


#### ▶ 5.4) Malware Upload — Payload Delivery via HTTP

HTTP multipart form uploads revealed transfer of executable content to the server, including:

- `3791.exe`
- `agent.php`

File upload activity was attributed to attacker IP `40.80.148.42`, confirming that malware was staged on the server after administrative access was obtained.


#### ▶ 5.5) Malware Execution — Host Telemetry Confirmation

Sysmon Event ID 1 (Process Creation) logs confirmed execution of:

- `3791.exe`

Process creation events included executable hash values and confirmed that the payload was executed on the host rather than merely uploaded. This validates transition from web compromise to host-level execution.


#### ▶ 5.6) Command and Control — Outbound Communication

Firewall and HTTP telemetry confirmed outbound connections from the compromised server to:

- **Domain:** `prankglassinebracket.jumpingcrab.com`
- **Associated IP:** `23.22.63.114`
- **Observed resource:** `poisonivy-is-coming-for-you-batman.jpeg`

This behavior confirms that the compromised server initiated communication with attacker infrastructure rather than receiving inbound control connections.


#### ▶ 5.7) Defacement Delivery — External Image Retrieval

Outbound HTTP requests from the server retrieved an externally hosted image which replaced or overrode homepage content, confirming:

- Modification of site content or templates to fetch attacker-controlled defacement material
- Successful completion of attacker objective

This mechanism explains why inbound attacker traffic was not observed during defacement display — the compromised server or visitor browsers pulled content from external infrastructure automatically.

---

### 6) Investigation Timeline (Condensed)

The timeline below reflects reconstructed attacker and server activity, not analyst workflow. Detailed investigation steps and Splunk queries are documented separately in: `investigation-walkthrough.md`

| Phase | Activity |
|--------|--------|
| T0 | Automated vulnerability scanning begins |
| T1 | Joomla admin paths targeted |
| T2 | Credential brute-force attempts observed |
| T3 | Successful admin authentication |
| T4 | Malicious payload uploaded |
| T5 | Malware executed on host |
| T6 | Outbound C2 communication initiated |
| T7 | Defacement image retrieved |
| T8 | Public defacement visible |

---

### 7) Indicators of Compromise (IOCs)

The indicators listed below represent high-confidence artifacts associated with reconnaissance, credential abuse, malware execution, and defacement observed during this intrusion.

Field-level telemetry and detection pivots are documented separately in: `detection-artifact-report.md`


#### ▶ 7.1) Network & Reconnaissance IOCs

These indicators reflect automated vulnerability scanning behavior.

- Scanning IP: `40.80.148.42`
- IDS signatures: Shellshock, SQLi, XSS, XXE
- User-Agent: `acunetix_wvs_security_test`

**Detection Use Cases:**
- Alert on vulnerability scanner signatures
- Detect malformed HTTP headers indicative of scanning


#### ▶ 7.2) Credential Abuse IOCs

These indicators reflect authentication targeting and compromise.

- Brute-force IP: `23.22.63.114`
- Compromised account: `admin`
- Successful login source: `40.80.148.42`

**Detection Use Cases:**
- Detect repeated POST attempts to admin endpoints
- Alert on successful login following failures


#### ▶ 7.3) Malware Delivery & Execution IOCs

These indicators reflect payload staging and execution.

- Uploaded file: `3791.exe`
- Additional artifact: `agent.php`

**Detection Use Cases:**
- Monitor file uploads via web applications
- Alert on executable creation in web directories


#### ▶ 7.4) Command and Control IOCs

These indicators reflect outbound attacker communication.

- Domain: `prankglassinebracket.jumpingcrab.com`
- Associated IP: `23.22.63.114`

**Detection Use Cases:**
- Detect servers initiating outbound HTTP to unknown domains
- Alert on dynamic DNS usage by servers


#### ▶ 7.5) Defacement Artifacts

These indicators reflect attacker objectives.

- Image file: `poisonivy-is-coming-for-you-batman.jpeg`

**Detection Use Cases:**
- Monitor external content inclusion in web templates
- Detect abnormal outbound fetches of media by servers


#### ▶ 7.6) IOC Limitations

While the indicators above are high-confidence within this investigation, attackers can change scanning tools, credential lists, payload names, and hosting domains. Detection strategies should prioritize behavioral correlations such as scanning followed by authentication success, file upload followed by execution, and server-initiated outbound connections rather than relying on static indicators.

---

### 8) Case Determination

**Final Determination:**  
Confirmed web server compromise involving credential abuse against Joomla administrative interface, followed by malware upload and execution, establishment of outbound command-and-control communication, and public website defacement.

Evidence supports a credential-driven web application intrusion rather than exploitation of unpatched software vulnerabilities.

---

### 9) Recommended Follow-Ups (Case Closure Actions)

The recommendations below summarize key containment, hardening, and detection priorities based on behaviors observed during this incident. Detailed technical controls are documented separately in: `detection-and-hardening-recommendations.md`

#### ▶ 9.1) Immediate Containment

- Take the web server offline
- Reset all administrative credentials
- Remove malicious files and modified templates
- Block attacker IPs and domains

#### ▶ 9.2) Hardening

- Enforce strong CMS authentication policies
- Enable MFA for administrative access
- Restrict file upload permissions
- Patch CMS and plugins

#### ▶ 9.3) Detection

- Alert on CMS admin brute-force attempts
- Monitor web servers for outbound traffic
- Detect file uploads followed by execution

---

### 10) Supporting Reports (In This Folder)

The files below make up the full case package for this investigation and provide additional detail across analyst workflow, response actions, detection engineering, and executive-level reporting.

- `investigation-walkthrough.md` — Step-by-step analyst workflow and Splunk queries  
- `incident-summary.md` — Executive-level narrative and business impact  
- `incident-response-report.md` — Containment and recovery actions  
- `detection-artifact-report.md` — Detection-relevant artifacts and telemetry  
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

- **Reconnaissance — Active Scanning (T1595)**
- **Initial Access — Brute Force (T1110)**
- **Initial Access — Valid Accounts (T1078)**
- **Execution — User Execution (T1204)**
- **Command and Control — Application Layer Protocol (T1071)**
- **Impact — Defacement (T1491)**

#### ▶ 11.2) MITRE ATT&CK Mapping (Table View)

| Tactic | Technique | Description |
|------|-----------|-------------|
| Reconnaissance | **Active Scanning (T1595)** | Automated vulnerability scanning against web services. |
| Initial Access | **Brute Force (T1110)** | Repeated credential attempts against Joomla admin login. |
| Initial Access | **Valid Accounts (T1078)** | Successful login using compromised admin credentials. |
| Execution | **User Execution (T1204)** | Uploaded malware executed on web server host. |
| Command and Control | **Application Layer Protocol (T1071)** | Outbound HTTP communication to attacker infrastructure. |
| Impact | **Defacement (T1491)** | Website content modified to display attacker message. |

---

