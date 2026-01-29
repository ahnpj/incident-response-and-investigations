# Case Report — Web Application Authentication Compromise Investigation (Brute-Force Attempts and Account Compromise Detection)

**Case Type:** Web Application Security Incident / Credential Access  
**Primary Abuse Pattern:** Automated authentication abuse involving account enumeration, password spraying, successful compromise, and credential reuse  
**Status:** Closed (investigation complete)  
**Confidence Level:** High — correlated application authentication logs, HTTP metadata, and credential exposure evidence

---

### 1) Executive Summary

This case investigates abnormal authentication activity against a web application that resulted in successful account compromise and subsequent credential reuse. Application-layer logs revealed a high volume of failed login attempts originating from a single external IP address, followed by successful authentication and reuse of the same credentials from a secondary source.

Analysis confirmed that the activity followed a full credential attack lifecycle, including automated brute-force behavior, account enumeration of non-existent users, password spraying against valid accounts, successful authentication, and reuse of compromised credentials. Further investigation revealed that the application logged credential material in a reversible encoded format, allowing plaintext password recovery.

Evidence supporting these conclusions includes repeated failed authentication attempts from a single source, consistent User-Agent values indicative of scripted tooling, shifts from non-existent to valid account targeting, successful authentication events, reuse of credentials from a new IP address, and reversible credential values stored in application logs.

---

### 2) Incident Background

The investigation was initiated following detection of elevated authentication failures within application authentication telemetry. Because credential abuse against web applications is a common initial access vector and can result in account takeover without malware or exploit activity, the investigation focused on reconstructing attacker behavior using application-layer logs.

The analysis sought to determine:

- Whether authentication attempts were automated or human-driven
- Whether the activity involved enumeration of valid accounts
- Whether any accounts were successfully compromised
- Whether compromised credentials were reused
- Whether application design weaknesses contributed to exposure

The goal was to validate account compromise, assess impact, and identify detection and prevention opportunities.

---

### 3) Scope

This section defines which systems, identities, and data sources were included in the investigation, as well as what activity was not observed within the available evidence. Clearly defining scope helps distinguish confirmed credential abuse from assumptions about broader system compromise that are not supported by telemetry.

#### ▶ 3.1) In-Scope

| Category | Included Items |
|--------|----------------|
| **Application Under Investigation** | • Linux-based web application |
| **Primary Evidence Sources** | • Application authentication telemetry |
| **Behavioral Focus Areas** | • Failed and successful authentication attempts<br>• Username targeting patterns<br>• Source IP behavior<br>• Credential handling and logging practices |

#### ▶ 3.2) Out-of-Scope / Not Observed

- Host-level compromise of application server
- Malware deployment
- Lateral movement
- Infrastructure takedown or attribution

Analysis was limited to post-incident review of application-layer authentication telemetry.

---

### 4) Environment

This investigation analyzed application-layer authentication telemetry to identify automated credential abuse against a web application.

#### ▶ 4.1) **Affected System (Victim) Operating System:**
- Linux-based web application server

#### ▶ 4.2) **Analyst Virtual Machine Operating System:**
- Windows-based analyst workstation used for log parsing and analysis

#### ▶ 4.3) **Platforms and Services:**
- Web application authentication service — reviewed login attempts, failures, and success events
- Application logging framework — extracted JSON-based authentication records for analysis

#### ▶ 4.4) **Data Sources Reviewed:**
- Application authentication logs (JSON format)
  - Username
  - Source IP address
  - Authentication result
  - Failure reason
- HTTP request metadata
  - Authentication endpoint
  - User-Agent string
- Stored credential fields within log records (encoded password values)

**Analyst Note:**  
No host-level telemetry or malware artifacts were available. Findings are limited to application-layer behavior and logging practices.

---

### 5) Evidence Summary

This section summarizes the primary evidence used to reconstruct automated authentication abuse, account enumeration, credential compromise, and reuse activity observed during this incident. It focuses on how each data source contributed to understanding attacker behavior and impact rather than listing raw log fields.

Detailed event fields, authentication parameters, and detection-relevant artifacts extracted from this investigation are documented separately in: `detection-artifact-report.md`


#### ▶ 5.1) Source IP Attribution — Automated Authentication Attempts

Authentication logs revealed a high volume of failed login attempts originating from a single external IP address within a short time window:

- **Attacking IP:** `198.51.100.100`

The concentration of failures from one source, combined with rapid request frequency, is inconsistent with legitimate user behavior and strongly indicative of scripted authentication abuse.


#### ▶ 5.2) User-Agent Consistency — Scripted Tooling Indicators

All authentication attempts originating from the attacking IP shared an identical User-Agent string:

- `Mozilla/5.0 (...) Chrome/91.0.4472.124 Safari/537.36`

The lack of variation across numerous requests suggests automated tooling configured to mimic a standard browser rather than interactive human logins.


#### ▶ 5.3) Account Enumeration — Non-Existent Username Targeting

Multiple authentication attempts targeted usernames that did not exist within the application, consistently returning failure responses indicating unrecognized accounts.

Non-existent usernames targeted included:

- `webmaster`
- `websitedev`
- `websitedbadmin`
- `websitebackup`
- `adminpanel`
- `loginpage`
- `adminpage`
- `adminservice`
- `websupport`

Targeting of generic administrative and service-style usernames indicates deliberate account enumeration rather than accidental user error.


#### ▶ 5.4) Targeted Credential Attacks — Valid Account Focus

After enumeration, authentication attempts shifted toward confirmed valid accounts, including:

- `websitemanager`
- `webadmin`
- `ftp`

These accounts are commonly associated with elevated privileges or service functionality, indicating prioritization of high-value targets following identification of valid users.


#### ▶ 5.5) Successful Authentication — Credential Compromise Confirmed

Following repeated failures, a successful authentication occurred for:

- **Compromised account:** `webadmin`
- **First successful login timestamp:** `2023-06-29T10:00:12`

Successful authentication occurred immediately after repeated failed attempts using identical client metadata, strongly indicating that correct credentials were obtained during the attack window.


#### ▶ 5.6) Credential Reuse — Secondary Source Authentication

Several minutes after initial compromise, the same account authenticated successfully from a new IP address:

- **Secondary IP:** `198.23.200.101`
- **Timestamp:** `2023-06-29T10:05:20`

This behavior indicates credential reuse rather than continued brute-force activity and confirms that valid credentials were compromised and operationally reused.


#### ▶ 5.7) Credential Exposure — Insecure Application Logging

Authentication logs contained a `hashed_password` field that remained consistent across failed and successful attempts. Decoding of this value revealed:

- **Encoded value:** `d2ViYWRtaW4xMjM0`
- **Recovered plaintext:** `webadmin1234`

The value was determined to be Base64-encoded rather than cryptographically hashed. Because Base64 is reversible, plaintext credentials could be recovered directly from application logs, representing a critical security failure and explaining the transition from failed attempts to successful authentication.

---

### 6) Investigation Timeline (Condensed)

The timeline below reflects the reconstructed sequence of attacker and application activity, not the step-by-step actions taken by the analyst during investigation. Detailed analyst workflow and data exploration are documented separately in: `investigation-walkthrough.md`

| Phase | Activity |
|--------|--------|
| T0 | High-volume authentication failures begin |
| T1 | Single attacking IP identified |
| T2 | Scripted behavior inferred via consistent User-Agent |
| T3 | Enumeration of non-existent accounts |
| T4 | Targeting of valid accounts |
| T5 | Successful authentication achieved |
| T6 | Credential reuse from secondary IP |
| T7 | Plaintext credential exposure confirmed in logs |

---

### 7) Indicators of Compromise (IOCs)

The indicators listed below represent high-confidence artifacts associated with authentication abuse, account compromise, and insecure credential handling observed during this incident.

Field-level telemetry and detection pivots are documented separately in: `detection-artifact-report.md`


#### ▶ 7.1) Network Source IOCs

- Primary attacking IP: `198.51.100.100`
- Secondary login IP: `198.23.200.101`

**Detection Use Cases:**
- Alert on excessive authentication failures from single sources
- Detect new successful logins from unfamiliar IPs

#### ▶ 7.2) User-Agent & Automation IOCs

- Consistent User-Agent: `Chrome/91.0.4472.124`

**Detection Use Cases:**
- Identify repeated authentication attempts using identical client metadata
- Flag automation patterns across multiple accounts


#### ▶ 7.3) Account Targeting IOCs

- Non-existent accounts targeted
- Valid accounts targeted: `websitemanager`, `webadmin`, `ftp`

**Detection Use Cases:**
- Alert on authentication attempts against invalid usernames
- Monitor targeting of privileged or service-style accounts


#### ▶ 7.4) Authentication Endpoint IOCs

- Targeted endpoint: `/api/login`

**Detection Use Cases:**
- Apply rate limiting and anomaly detection to authentication endpoints
- Monitor for bursts of failed authentication activity per endpoint


#### ▶ 7.5) Credential Exposure Artifacts

- Base64-encoded credential values in logs
- Recoverable plaintext passwords

**Detection Use Cases:**
- Audit application logs for sensitive credential material
- Detect deterministic credential values across login attempts


#### ▶ 7.6) IOC Limitations

While the indicators above are high-confidence within this dataset, attackers can change IP infrastructure, User-Agent strings, and username lists. Detection strategies should prioritize behavioral correlations such as enumeration followed by successful authentication rather than relying solely on static indicators.

---

### 8) Case Determination

**Final Determination:**  
Confirmed web application account compromise resulting from automated authentication abuse combined with insecure credential handling in application logs, leading to successful login and credential reuse.

Evidence supports a credential access incident involving brute-force behavior, password spraying, account enumeration, and unsecured credential exposure rather than exploitation of software vulnerabilities.

---

### 9) Recommended Follow-Ups (Case Closure Actions)

The recommendations below summarize key containment, hardening, and detection priorities based on behaviors observed during this incident. Detailed technical controls and expanded monitoring strategies are documented separately in: `detection-and-hardening-recommendations.md`

#### ▶ 9.1) Immediate Containment

- Reset credentials for all affected and targeted accounts
- Invalidate active authentication sessions
- Block or rate-limit identified attacking IP addresses

#### ▶ 9.2) Hardening

- Implement account lockout and progressive backoff controls
- Enforce multi-factor authentication for privileged accounts
- Remove credential material from application logs
- Ensure passwords are securely hashed and salted

#### ▶ 9.3) Detection

- Alert on enumeration of non-existent usernames
- Detect successful authentication following repeated failures
- Monitor reuse of credentials from new IP addresses

---

### 10) Supporting Reports (In This Folder)

The files below make up the full case package for this investigation and provide additional detail across analyst workflow, response actions, detection engineering, and executive-level reporting.

- `investigation-walkthrough.md` — Step-by-step analyst workflow and evidence validation  
- `incident-summary.md` — Executive-level narrative and business impact  
- `incident-response-report.md` — Containment and recovery actions  
- `detection-artifact-report.md` — Authentication fields and detection pivots  
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

- **Credential Access — Brute Force (T1110)**
- **Credential Access — Password Spraying (T1110.003)**
- **Credential Access — Valid Accounts (T1078)**
- **Credential Access — Unsecured Credentials (T1552)**

#### ▶ 11.2) MITRE ATT&CK Mapping (Table View)

| Tactic | Technique | Description |
|--------|----------|-------------|
| Credential Access | **Brute Force (T1110)** | High-volume authentication failures from single source |
| Credential Access | **Password Spraying (T1110.003)** | Repeated attempts across multiple usernames |
| Credential Access | **Valid Accounts (T1078)** | Successful authentication using compromised credentials |
| Credential Access | **Unsecured Credentials (T1552)** | Plaintext credentials recoverable from logs |

---

