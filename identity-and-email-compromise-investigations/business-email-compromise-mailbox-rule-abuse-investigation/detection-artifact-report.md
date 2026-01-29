# Detection Artifact Report — Business Email Compromise (BEC) Investigation (Malicious Mailbox Rule Abuse and Account Compromise)

### 1) Purpose and Scope

This report documents **detection-relevant identity, mailbox, and email workflow artifacts** observed during investigation of a Business Email Compromise (BEC) incident involving unauthorized cloud sign-ins and malicious mailbox rule creation used to hide fraudulent financial communications.

The objective of this report is to provide **evidence-backed, investigation-anchored indicators** that can be used for:

- SIEM detection engineering and correlation rules
- Identity protection monitoring
- Exchange Online mailbox auditing
- Threat hunting across cloud audit telemetry

All artifacts in this report are derived from investigation pivots and validation steps documented in:

- `business-email-compromise-mailbox-rule-abuse-investigation.md` — analyst workflow, log pivots, and evidence validation  
- `case-report.md` — reconstructed attacker timeline and confirmed business impact  
- `MITRE-ATT&CK-mapping.md` — technique classification and behavioral context  

This report complements:

- `incident-response-report.md` — containment, eradication, and recovery procedures  
- `detection-and-hardening-recommendations.md` — long-term preventive and monitoring controls  

---

### 2) Environment and Log Sources

This section summarizes telemetry sources used to identify and validate BEC-related artifacts.

#### ▶ 2.1) Primary data sources used during investigation

- **Microsoft Entra ID (Azure AD) Sign-In Logs**
  - Successful and failed authentication attempts
  - IP address, device, browser, and location metadata

- **Microsoft Entra ID Audit Logs**
  - Mailbox configuration changes
  - Inbox rule creation and modification events

- **Microsoft Exchange Online Mailbox Audit Logs**
  - Inbox rule properties
  - Mailbox access activity

- **Email Message Artifacts**
  - Fraud-related pension withdrawal communications
  - Timestamp correlation with rule creation and sign-in activity

#### ▶ 2.2) Affected identity and mailbox

- **Victim user:** Employee participating in pension withdrawal workflow  
- **Mailbox platform:** Exchange Online (cloud-hosted)  
- **Attack surface:** Identity and mailbox configuration (no endpoint compromise observed)

---

### 3) High-Confidence Attack Sequence Anchors

This section documents timeline anchors used to align identity, mailbox, and business-process artifacts.

| Anchor Event | Description | Evidence Source | Investigation Pivot |
|--------|-------------|------------------|---------------------|
| Anomalous sign-ins | Login attempts from unfamiliar IPs | Entra ID Sign-In Logs | Triggered identity triage |
| Successful compromise | First successful foreign login | Entra ID Sign-In Logs | Confirmed account takeover |
| Persistence action | Inbox rule creation | Entra ID Audit Logs | Identified stealth mechanism |
| Business manipulation | Pension workflow emails hidden | Mailbox artifacts | Validated fraud risk |
| Continued access | Repeated sessions post-rule | Sign-In Logs | Confirmed sustained control |

These anchors were used to correlate identity abuse with mailbox manipulation and business impact.

---

### 4) Identity and Authentication Artifacts

This section documents authentication behaviors indicating unauthorized access to the cloud account.

#### ▶ 4.1) Artifact: Successful Sign-In from Unfamiliar IP and Location

**Observed Behavior:**

- Successful Entra ID authentication from IP addresses and geographic locations not previously associated with the user account.

**Where Identified in Investigation:**  
During initial triage of the reported pension-related issue, analysts first reviewed Entra ID Sign-In Logs for the affected user to determine whether the mailbox had been accessed by external parties. This review revealed successful logins originating from foreign IP addresses that did not align with the user’s known working locations or historical access patterns. These sessions were time-correlated with the onset of suspicious mailbox behavior, prompting escalation from mailbox troubleshooting to confirmed identity compromise investigation.

**Behavioral Significance:**

- Indicates credential compromise or session token abuse.
- Establishes initial access vector enabling mailbox configuration changes.

**Detection Guidance:**

- Alert when:
  - successful login occurs from new country, ASN, or impossible travel patterns.
- Increase severity when:
  - followed by mailbox configuration changes or rule creation events.


#### ▶ 4.2) Artifact: Failed Authentication Attempts Preceding Successful Login

**Observed Behavior:**

- Multiple failed authentication attempts prior to the successful compromise login.

**Where Identified in Investigation:**  
After identifying the successful foreign login, analysts pivoted backward in time within the same Sign-In Log dataset to assess whether the account experienced prior authentication failures. This retrospective review showed a pattern of failed attempts from the same external network shortly before the successful login, supporting the hypothesis of password guessing or credential stuffing rather than session hijacking.

**Behavioral Significance:**

- Suggests brute-force or credential-stuffing activity.
- Increases confidence that compromise resulted from password-based access.

**Detection Guidance:**

- Correlate:
  - repeated failures followed by success from same IP or ASN.
- Escalate to high severity when:
  - failures transition to success within short time window.

---

### 5) Mailbox Configuration and Persistence Artifacts

This section documents how attackers established stealthy persistence and hid their activity.

#### ▶ 5.1) Artifact: Creation of Malicious Inbox Rule

**Observed Artifact:**

- New inbox rule created without user authorization.
- Rule actions configured to:
  - move or delete messages related to financial workflows.
- Rule conditions matched keywords associated with pension communications.

**Where Identified in Investigation:**  
Once identity compromise was confirmed, analysts pivoted from Sign-In Logs to Entra ID Audit Logs and Exchange mailbox audit data to determine whether mailbox configuration had been modified. This review revealed the creation of a new inbox rule shortly after the suspicious login. Analysts then inspected rule conditions and actions directly within mailbox audit records, confirming that messages related to the pension withdrawal process were being automatically removed from the inbox, explaining why the user did not see critical communications.

**Behavioral Significance:**

- Serves as mailbox-level persistence mechanism.
- Enables attacker to remain hidden while monitoring and manipulating conversations.

**Detection Guidance:**

- Alert when:
  - new inbox rules are created or modified.
- Increase severity when:
  - rule actions include delete, move, or forward.
  - rule conditions reference financial or HR keywords.


#### ▶ 5.2) Artifact: Continued Mailbox Access After Rule Creation

**Observed Behavior:**

- Repeated successful sign-ins from same suspicious IP after inbox rule was created.

**Where Identified in Investigation:**  
After confirming inbox rule creation, analysts returned to Sign-In Logs to assess whether attacker access continued. Timeline correlation showed multiple additional sessions from the same unfamiliar IP following rule deployment, indicating the attacker remained actively engaged with the mailbox rather than performing a one-time configuration change.

**Behavioral Significance:**

- Confirms sustained attacker control over the mailbox.
- Indicates monitoring of conversations and possible response manipulation.

**Detection Guidance:**

- Alert when:
  - mailbox configuration changes are followed by repeated foreign sign-ins.
- Use as indicator of ongoing BEC operation rather than isolated access.

---

### 6) Email and Business Process Manipulation Artifacts

This section documents evidence of direct impact on business workflows.

#### ▶ 6.1) Artifact: Legitimate Pension Emails Hidden from User Inbox

**Observed Behavior:**

- Legitimate emails related to pension withdrawal were not visible in the inbox.
- Messages were located in deleted items or alternate folders.

**Where Identified in Investigation:**  
After inbox rule behavior was identified, analysts conducted mailbox searches and reviewed audit logs to trace message disposition. This revealed that legitimate pension-related communications had been processed by the malicious rule and moved or deleted automatically, confirming that the attacker intentionally prevented the user from seeing time-sensitive financial messages.

**Behavioral Significance:**

- Confirms operational impact on financial process.
- Demonstrates attacker intent to manipulate business workflow rather than simply access email.

**Detection Guidance:**

- Alert when:
  - inbox rules match financial keywords.
- Monitor sudden drops in visible financial communications.


#### ▶ 6.2) Artifact: Attacker-Sent Messages Using Victim Account

**Observed Behavior:**

- Emails sent from victim mailbox to external pension-related contacts.

**Where Identified in Investigation:**  
Investigators reviewed message tracking and email headers to validate whether outbound messages originated from the legitimate mailbox rather than spoofed addresses. Timestamp correlation showed these messages were sent during periods when suspicious sign-in sessions were active, confirming that the attacker was actively impersonating the user to interact with third parties.

**Behavioral Significance:**

- Confirms full business email compromise rather than simple email forwarding.
- Indicates attacker participation in ongoing financial workflow.

**Detection Guidance:**

- Alert on:
  - unusual sending patterns.
- Escalate when:
  - recipients involve financial institutions or payroll providers.

---

### 7) Absence of Endpoint Compromise Artifacts

This section documents negative findings that narrowed incident scope.

#### ▶ 7.1) Artifact: No Evidence of Endpoint-Based Access

**Observed Behavior:**

- No device-based authentication or VPN sessions associated with suspicious sign-ins.
- No endpoint alerts or malware indicators.

**Where Verified in Investigation:**  
Analysts reviewed device identifiers and authentication methods in Entra ID logs and confirmed that access originated from browser-based sessions rather than corporate-managed endpoints. This, combined with lack of EDR alerts, supported the conclusion that compromise occurred through credential abuse rather than malware infection on the user’s device.

**Detection Implications:**

- Confirms incident was identity-based.
- Guides remediation toward credential resets rather than endpoint reimaging.

---

### 8) Cross-Source Correlation Opportunities

This section outlines detection strategies that mirror investigation pivots.

#### ▶ 8.1) Correlation 1: Anomalous Login → Inbox Rule Creation

**Signals:**

- Successful sign-in from new IP/geo
- Inbox rule created shortly afterward

**Use Case:**  
High-confidence indicator of mailbox takeover used for stealth persistence.


#### ▶ 8.2) Correlation 2: Inbox Rule Creation → Financial Workflow Emails

**Signals:**

- Rule matching finance-related keywords
- Emails involving financial actions

**Use Case:**  
Detects fraud-in-progress rather than generic mailbox abuse.

#### ▶ 8.3) Correlation 3: Persistent Sign-Ins from Same Foreign IP

**Signals:**

- Repeated sessions from same unfamiliar source

**Use Case:**  
Indicates active attacker monitoring and interaction.

---

### 9) Indicator Reliability Considerations

This section distinguishes behavioral indicators from easily changed values.

**Low reliability indicators:**

- Rule names
- Specific subject keywords

**Higher reliability indicators:**

- Rule actions (delete, move, forward)
- Identity anomaly + mailbox configuration correlation
- Repeated access from same foreign infrastructure

Behavior-based detection reduces evasion risk.

---

### 10) Closing Summary

This investigation demonstrates how attackers can conduct effective BEC operations entirely through:

- credential abuse
- mailbox configuration manipulation
- impersonation of legitimate users

without deploying malware or touching endpoints.

Reliable detection depends on correlating:

- identity anomalies,
- mailbox audit events,
- and business process communications.

Organizations that monitor mailbox configuration changes in the context of identity risk signals can detect BEC campaigns before financial loss occurs.

