# Detection Artifact Report — Web Application Authentication Compromise Investigation (Brute-Force Attempts and Account Compromise Detection)

### 1) Purpose and Scope

This report documents **web, authentication, and session-related artifacts** observed during investigation of web application authentication abuse involving repeated login attempts, successful credential compromise, and post-authentication application access.

The purpose of this report is to provide **detection-engineering–ready indicators that are directly tied to analyst investigation pivots**, showing how evidence was discovered, validated, and correlated across web and identity telemetry.

Artifacts are mapped to how they were identified during investigation, reflecting realistic SOC workflows that move from abnormal web traffic to confirmation of authenticated abuse.

All artifacts are derived from investigative steps documented in:

- `web-application-authentication-abuse-investigation.md` — analyst pivots, log queries, and validation workflow  
- `case-report.md` — reconstructed attacker timeline and business impact  
- `MITRE-ATT&CK-mapping.md` — technique classification and behavioral context  

This report complements:

- `incident-response-report.md` — containment and remediation sequencing  
- `detection-and-hardening-recommendations.md` — preventive and monitoring controls  

---

### 2) Environment and Log Sources

This section summarizes telemetry sources used to identify and validate authentication abuse artifacts.

#### ▶ 2.1) Primary telemetry sources referenced in investigation

- **Web Server Access Logs**
  - HTTP request methods, status codes, URIs
  - Source IP addresses and timestamps

- **Application Authentication Logs**
  - Login success and failure events
  - User identifiers and session creation timestamps

- **Firewall / Network Logs**
  - Source IP reputation and connection patterns

- **Splunk Web and Authentication Data Models**
  - Web.Access
  - Authentication

#### ▶ 2.2) Affected system

- **Target application:** Public-facing web application with login functionality  
- **Attack surface:** HTTP authentication endpoints

---

### 3) High-Confidence Investigation Anchors

This section documents timeline anchors that structured investigative correlation.

| Anchor Event | Description | Evidence Source | Investigation Pivot |
|--------|-------------|------------------|---------------------|
| Login abuse detected | High volume of POST requests to login | Web access logs | Triggered auth abuse review |
| Credential success | Successful login from attacker IP | App auth logs | Confirmed account compromise |
| Session creation | Authenticated session established | App logs | Validated post-auth access |
| Sensitive endpoint access | Access to protected resources | Web logs | Confirmed abuse impact |
| Continued login activity | Repeated access over time | Web + auth logs | Confirmed sustained misuse |

These anchors were used to correlate unauthenticated abuse with authenticated application exploitation.

---

### 4) Web Authentication Abuse Artifacts

This section documents artifacts indicating credential abuse.

#### ▶ 4.1) Artifact: Repeated POST Requests to Login Endpoint

**Observed Behavior:**

- High volume of POST requests to authentication URI from a single external IP.

**Where Identified in Investigation:**  
Analysts began by reviewing web access logs after alerts indicated abnormal request volume to the login page. Filtering for POST requests to the authentication endpoint revealed repeated attempts from the same source IP over a short time window, prompting hypothesis of brute-force or credential-stuffing activity rather than normal user behavior.

**Behavioral Significance:**

- Indicates automated credential testing.
- Differentiates malicious traffic from normal browsing.

**Detection Guidance:**

- Alert when:
  - repeated POSTs to login endpoint exceed baseline thresholds
- Correlate with:
  - authentication failure events


#### ▶ 4.2) Artifact: Authentication Failures Followed by Success

**Observed Behavior:**

- Multiple failed login attempts followed by successful authentication from same IP.

**Where Identified in Investigation:**  
After identifying repeated login attempts in web logs, analysts pivoted into application authentication logs to validate whether attempts resulted in account compromise. This revealed a sequence of failures followed by success originating from the same source IP, confirming credential compromise rather than simple scanning.

**Behavioral Significance:**

- Strong indicator of successful brute-force or credential stuffing.
- Establishes transition from recon to initial access.

**Detection Guidance:**

- Alert on:
  - failure-to-success transitions from same source
- Increase severity when:
  - followed by session creation

---

### 5) Post-Authentication Access Artifacts

This section documents abuse of authenticated sessions.

#### ▶ 5.1) Artifact: Session Creation After Successful Login

**Observed Behavior:**

- Application session created for compromised user account.

**Where Identified in Investigation:**  
Following confirmation of successful authentication, analysts reviewed application session logs to verify that the attacker established persistent access. Session creation timestamps aligned with the successful login event, confirming that authentication resulted in active application access rather than blocked attempts.

**Behavioral Significance:**

- Confirms usable compromise rather than transient access.
- Enables subsequent application abuse.

**Detection Guidance:**

- Alert when:
  - new sessions originate from IPs associated with prior failures


#### ▶ 5.2) Artifact: Access to Protected Application Endpoints

**Observed Behavior:**

- HTTP GET/POST requests to restricted resources requiring authentication.

**Where Identified in Investigation:**  
After validating session creation, analysts returned to web logs and filtered for requests using authenticated session identifiers. This revealed access to application areas not available to unauthenticated users, confirming that the attacker leveraged valid credentials to interact with sensitive application functionality.

**Behavioral Significance:**

- Demonstrates business impact of credential compromise.
- Confirms exploitation of authorized features.

**Detection Guidance:**

- Alert when:
  - protected endpoints are accessed from previously failing IPs

---

### 6) Persistence and Continued Abuse Artifacts

This section documents sustained attacker activity over time.

#### ▶ 6.1) Artifact: Repeated Authenticated Access from Same External IP

**Observed Behavior:**

- Continued login sessions and resource access from attacker IP over extended period.

**Where Identified in Investigation:**  
Analysts expanded the timeline review window after initial compromise detection to determine whether abuse was ongoing. Correlation of web and authentication logs showed repeated sessions from the same external IP across multiple time intervals, indicating sustained exploitation rather than a one-time incident.

**Behavioral Significance:**

- Confirms attacker maintaining access.
- Suggests monitoring of user activity or data exfiltration risk.

**Detection Guidance:**

- Alert when:
  - same external IP repeatedly authenticates to sensitive accounts

---

### 7) Absence of Application Exploit Artifacts

This section documents negative findings that informed incident classification.

#### ▶ 7.1) Artifact: No Evidence of SQL Injection or Exploit Payloads

**Observed Behavior:**

- No abnormal query strings or exploit signatures in web requests.

**Where Verified in Investigation:**  
During analysis of web traffic, analysts inspected request parameters and payloads for exploit patterns such as SQL injection or deserialization attempts. The absence of such payloads confirmed that compromise occurred through authentication abuse rather than application vulnerability exploitation.

**Detection Implications:**

- Incident classified as credential-based abuse.
- Remediation focused on authentication controls rather than patching.

---

### 8) Cross-Source Correlation Opportunities

This section outlines detection strategies based on investigation pivots.

#### ▶ 8.1) Correlation 1: Web Login Flood → Authentication Failures

**Signals:**

- Web POST requests to login endpoint
- Authentication failure logs

**Use Case:**  
Detect brute-force attempts in progress.


#### ▶ 8.2) Correlation 2: Failure → Success Transition

**Signals:**

- Authentication failures followed by success from same IP

**Use Case:**  
Detect confirmed account compromise.


#### ▶ 8.3) Correlation 3: Compromise → Protected Resource Access

**Signals:**

- Successful authentication
- Requests to restricted endpoints

**Use Case:**  
Detect business-impacting application abuse.

---

### 9) Indicator Reliability Considerations

This section distinguishes between fragile indicators and reliable behaviors.

**Low reliability indicators:**

- Source IP addresses
- User-agent strings

**Higher reliability indicators:**

- Failure-to-success authentication patterns
- Authenticated access following brute-force activity
- Sustained authenticated sessions from unusual locations

Behavior-based detection remains effective even when attackers rotate infrastructure.

---

### 10) Closing Summary

This investigation demonstrated how attackers can gain full application access without exploiting software vulnerabilities by abusing:

- weak authentication controls
- lack of rate limiting
- insufficient anomaly detection

By correlating:

- web request patterns,
- authentication outcomes,
- and session activity,

analysts were able to confirm credential compromise and scope application-level impact.

Detection strategies that link **unauthenticated abuse with post-authenticated activity** provide high-confidence identification of web application account compromise and enable faster containment.

