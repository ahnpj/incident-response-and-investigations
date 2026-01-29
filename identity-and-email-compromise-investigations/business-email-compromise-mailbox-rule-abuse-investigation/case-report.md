# Case Report — Business Email Compromise (BEC) Investigation (Malicious Mailbox Rule Abuse and Account Compromise)

**Case Type:** Business Email Compromise (BEC)  
**Primary Abuse Pattern:** Compromised executive mailbox used to approve fraudulent pension withdrawals, with concealment via inbox rules and hidden folders  
**Status:** Closed (investigation complete)  
**Confidence Level:** High — correlated email artifacts, authentication telemetry, and mailbox configuration evidence

---

### 1) Executive Summary

This case investigates a Business Email Compromise incident in which an executive Microsoft 365 mailbox was compromised and used to authorize fraudulent pension withdrawals. Email artifacts show impersonation of a trusted pension provider to establish legitimacy, while Azure Active Directory audit telemetry confirms unauthorized authentication followed by deliberate mailbox configuration changes.

The attacker created inbox rules that filtered messages containing financial keywords and routed them into a hidden folder, effectively suppressing transaction confirmations and approval correspondence. This concealment delayed detection and enabled unauthorized financial transactions to proceed using the executive’s legitimate approval authority.

Evidence supporting these conclusions includes:

- External impersonation emails establishing financial context (see *Investigation Walkthrough → Initial Access Analysis*, Figure 1)
- Successful authentication events for the executive account from suspicious IP addresses (see *Post-Compromise Activity → Identifying Threat Actor IP Addresses*, Figure 3)
- Inbox rule creation events targeting financial keywords (see *Identifying the Inbox Rule Keyword*, Figure 11)
- Rule actions routing emails to a hidden folder named `History` (see *Mailbox Manipulation → Inbox Folder Creation*, Figure 9)

---

### 2) Incident Background

The organization observed multiple unauthorized yet approved pension withdrawals processed over approximately a 48-hour period. Because the transactions were approved using an executive mailbox with legitimate authority, and no endpoint malware indicators were present, the incident was investigated as identity and email compromise rather than host-based intrusion.

The investigation focused on reconstructing attacker behavior using email artifacts and Azure Active Directory audit logs to determine:

- How initial contact and trust were established
- Whether and how the mailbox was accessed by unauthorized actors
- How email workflows were manipulated to conceal financial activity
- What indicators would be available for detection and response in a real environment

This mirrors a post-incident SOC investigation where financial anomalies trigger retrospective identity and mailbox analysis.

---

### 3) Scope

This section defines which identities, mailboxes, and data sources were included in the investigation of this Business Email Compromise incident, as well as what activity was not observed within the available evidence. Clearly defining scope helps distinguish confirmed identity and mailbox abuse from assumptions about broader network or endpoint compromise that are not supported by telemetry.

#### ▶ 3.1) In Scope

| Category | Included Items |
|--------|----------------|
| **Compromised Mailbox** | • `becky.lorray@tempestasenergy.com` (executive approval authority) |
| **Primary Evidence Sources** | • Email artifacts reviewed via Thunderbird<br>• Azure Active Directory audit log export (`azure-export-audit-dir.csv`) |
| **Behavioral Focus Areas** | • Authentication activity<br>• Inbox folder creation<br>• Inbox rule configuration and abuse<br>• Financial workflow communications |

#### ▶ 3.2) Out of Scope / Not Observed

- Endpoint malware execution
- Exploit-based initial access
- Persistence mechanisms beyond mailbox configuration abuse

No evidence of endpoint compromise or malicious attachments was observed within the dataset provided.

---

### 4) Environment

This investigation analyzed identity and email service abuse within a cloud-hosted environment using centralized audit and authentication telemetry.

#### ▶ 4.1)  **Affected System (Victim) Operating System:**
- Not applicable — cloud-hosted Microsoft 365 services (no endpoint compromise observed)

#### ▶ 4.2) **Analyst Virtual Machine Operating System:**
- Windows-based analyst workstation used for log and email artifact review

#### ▶ 4.3) **Platforms and Services:**
- Microsoft Entra ID (Azure Active Directory) — reviewed authentication activity, source IPs, and account access patterns
- Microsoft Exchange Online — analyzed mailbox configuration changes and inbox rule abuse
- Microsoft Purview / Audit Export — used to retrieve mailbox rule and audit event data

#### ▶ 4.4) **Data Sources Reviewed:**
- Azure AD Sign-In Logs (authentication attempts, source IPs, success/failure)
- Azure AD Audit Logs (mailbox rule creation and configuration changes)
- Email message artifacts (headers, sender domains, and message body content)
- Mailbox rule configuration records (rule conditions and suppression actions)

**Analyst Note:**  
Findings are based exclusively on identity and mailbox configuration telemetry consistent with Business Email Compromise (BEC) tradecraft.


---

## 5) Evidence Summary

This section summarizes the primary evidence used to reconstruct identity abuse, mailbox manipulation, and fraudulent financial workflow activity observed during this Business Email Compromise incident. It focuses on how each data source (email artifacts, authentication telemetry, and mailbox configuration logs) contributed to understanding attacker behavior and impact, rather than listing all raw log fields or detection logic.

Detailed event fields, mailbox rule parameters, authentication attributes, and detection-relevant artifacts extracted from this investigation are documented separately in: `detection-artifact-report.md`

This separation reflects common SOC workflows for BEC investigations, where incident narratives and detection engineering references are maintained as distinct artifacts.


#### ▶ 5.1 Email Artifacts — Initial Social Engineering

Initial review focused on email artifacts to identify pre-authentication attacker activity. Because phishing and impersonation occur before identity logs record any activity, email analysis was used to establish how trust and financial context were created.

Header analysis of financial approval messages revealed the sender:

- **From:** `Sabastian Hague <sabastian@flanaganspensions.co.uk>`
- **To:** `becky.lorray@tempestasenergy.com`
- **Cc:** `liam.fray@tempestasenergy.com`

This impersonated pension provider aligns with common BEC tactics where attackers pose as trusted third parties involved in financial workflows.  
(See *Initial Access Analysis: Email Artifact Review*, Figure 1)


#### ▶ 5.2 Authentication Evidence — Credential-Based Access

After establishing external impersonation, investigation pivoted to Azure AD audit logs to validate unauthorized mailbox access.

Because sign-in logs were not separately provided, authentication events were identified within the audit export as:

- `Operation = UserLoggedIn`

Search criteria used: `UserLoggedIn,becky.lorray@tempestasenergy.com`

Inspection of the embedded audit JSON identified repeated authentication from two external IP addresses:

- `159.203.17.81`
- `95.181.232.30`

These IPs were associated with successful authentication events followed by mailbox interaction and configuration changes, establishing them as attacker-controlled infrastructure.  
(See *Post-Compromise Activity → Identifying Threat Actor IP Addresses*, Figure 3)

Other IPs were observed but excluded due to lack of follow-on mailbox activity.


#### ▶ 5.3 Financial Workflow Evidence — Destination Bank Attribution

Financial attribution was derived from email content rather than audit telemetry, as Azure logs do not capture external banking details.

The withdrawal email titled:

- **Subject:** `20250702-Withdrawal-Bernard`

Contained the following banking metadata:

- **SWIFT/BIC:** `FBNINGLA`
- **Account Number:** `3025819476`

SWIFT code `FBNINGLA` corresponds to **First Bank of Nigeria Plc**, establishing the receiving financial institution for the fraudulent transfer.  
(See *Financial Impact: Identifying the Destination Bank*, Figure 4)


#### ▶ 5.4 Mailbox Manipulation — Folder Creation & Inbox Rules

##### 5.4.1 Folder Creation

Audit logs revealed `FolderCreated` events associated with the compromised mailbox on:

- `2025-07-01`
- `2025-07-02`

These occurred after confirmed attacker authentication sessions, indicating mailbox manipulation during active compromise.  
(See *Mailbox Manipulation → Inbox Folder Creation*, Figures 5–7)

Folder names were not reliably recorded in `FolderCreated` events.


##### 5.4.2 Inbox Rule Abuse (Primary Concealment Mechanism)

To identify how emails were routed, investigation pivoted to inbox rule creation events:

- `Operation = New-InboxRule`

The first rule created for the compromised account contained:

**Condition:**

```json
"Name":"BodyContainsWords","Value":"withdrawal"
"Name":"MoveToFolder","Value":"History"
"Name":"DeleteMessage","Value":"True"
"Name":"StopProcessingRules","Value":"True"
```

This confirms that:

- Financial emails containing “withdrawal” were intercepted
- Messages were routed into a folder named History
- Messages could be deleted and excluded from further rule processing

This configuration demonstrates deliberate suppression of financial communications.
(See Identifying the Inbox Rule Keyword, Figure 11 and Inbox Folder Identification, Figure 9)

PowerShell validation confirmed identical rule parameters.
(See Confirmed via PowerShell, Figure 10)

---

### 6) Investigation Timeline (Condensed)
 
The timeline below reflects the **reconstructed sequence of attacker activity and business impact**, not the step-by-step actions taken by the analyst during the investigation. Detailed analyst workflow, tool usage, and investigative pivots are documented separately in the full investigation walkthrough:  `investigation-walkthrough.md`  

This distinction mirrors real-world incident response reporting, where one timeline describes **what happened**, while another documents **how it was discovered**.

| Phase | Activity |
|------|----------|
| T0 | External impersonation email establishes financial workflow context |
| T1 | Successful authentication to executive mailbox from attacker IPs |
| T2 | Inbox folder created during active attacker session |
| T3 | Inbox rule created filtering “withdrawal” and routing to History |
| T4 | Fraudulent withdrawal communications suppressed |
| T5 | Case classified as confirmed Business Email Compromise |

---

## 7) Indicators of Compromise (IOCs)

The indicators listed below represent high-confidence artifacts associated with identity compromise, mailbox rule abuse, and fraudulent financial communication workflows observed during this Business Email Compromise incident. These IOCs are presented at a conceptual and operational level to support threat hunting, alerting, and scoping of similar activity across executive and finance mailboxes.

Field-level telemetry, mailbox audit parameters, authentication attributes, and example detection logic derived from these indicators are documented separately in: `detection-artifact-report.md`

That report is intended for SOC analysts and detection engineers responsible for implementing monitoring and alerting controls related to email-based fraud and identity abuse.


#### ▶ 7.1 Identity & Authentication IOCs

These indicators relate to unauthorized access to the compromised mailbox and are useful for identifying credential abuse, anomalous authentication patterns, and potential reuse of attacker infrastructure across additional identity compromise attempts.

**Confirmed attacker authentication sources:**
- `159.203.17.81`
- `95.181.232.30`

**Associated activity:**
- Azure AD audit events with `Operation = UserLoggedIn`
- Target account: `becky.lorray@tempestasenergy.com`
- Follow-on actions included mailbox configuration changes and inbox rule creation

**Detection Use Cases:**
- Successful authentication from new or rare IP addresses for executive accounts
- Authentication followed closely by mailbox configuration changes
- Repeated logins from unfamiliar infrastructure within short time windows


#### ▶ 7.2 Mailbox Manipulation IOCs

These indicators reflect deliberate mailbox configuration changes used to conceal financial communications and maintain attacker control over message visibility. They are useful for detecting persistence mechanisms based on inbox rule abuse and hidden folder routing.

**Hidden or attacker-used inbox folder:**
- `History`

**Inbox rule condition keyword:**
- `withdrawal`

**Inbox rule actions observed:**
- `MoveToFolder = History`
- `DeleteMessage = True`
- `StopProcessingRules = True`

**Associated audit events:**
- `Operation = New-InboxRule`
- `Operation = FolderCreated`

**Detection Use Cases:**
- New inbox rules containing financial or security-related keywords
- Rules that move or delete messages rather than flag or forward
- Folder creation events shortly after new authentication sessions
- Rules configured with `StopProcessingRules` to suppress downstream rules


#### ▶ 7.3 Email-Based IOCs (Social Engineering Infrastructure)

These indicators relate to external impersonation and fraudulent communication patterns used to establish trust and initiate the financial workflow. They are useful for detecting similar social engineering attempts targeting executive or finance personnel.

**Impersonated sender identity:**
- Display name: `Sabastian Hague`
- Email address: `sabastian@flanaganspensions.co.uk`

**Email themes observed:**
- Pension withdrawal approvals
- Urgent financial authorization language
- Third-party pension administrator context

**Detection Use Cases:**
- External senders impersonating financial service providers
- New external contacts initiating financial workflow changes
- Executive-targeted emails referencing payment or approval processes


#### ▶ 7.4 Financial Workflow IOCs

These indicators reflect banking and transaction-related metadata observed in withdrawal communications and are useful for identifying fraudulent payment destinations, monitoring for unusual financial routing, and supporting fraud investigations.

**Receiving financial institution identifiers:**
- SWIFT/BIC: `FBNINGLA`
- Bank: First Bank of Nigeria Plc

**Account reference observed:**
- `3025819476`

**Email artifacts referencing transactions:**
- Subject pattern: `*Withdrawal*`
- Example: `20250702-Withdrawal-Bernard`

**Detection Use Cases:**
- Monitoring for international transfers involving new banking institutions
- Flagging approvals referencing unfamiliar SWIFT codes
- Correlating email approvals with transaction execution windows


#### ▶ 7.5 IOC Limitations

While the indicators above are high-confidence within this investigation, many can be easily changed by attackers, including sender identities, inbox rule keywords, and destination accounts. As a result, detection strategies should prioritize behavioral correlations such as anomalous logins followed by mailbox rule creation rather than relying solely on static indicators.

- IP addresses may represent shared or transient infrastructure and should not be relied upon as long-term blocking indicators alone.
- Email sender identities may be rotated or spoofed in future campaigns.
- Financial account numbers are often changed between fraud attempts.

As a result, detection strategies should prioritize **behavioral indicators** (authentication + mailbox manipulation sequences) over static indicators alone.

Behavioral correlation remains the most reliable method for detecting similar Business Email Compromise activity at scale.

---

## 8) Case Determination

Final Determination:
Confirmed Business Email Compromise involving credential-based mailbox access followed by mailbox rule abuse to conceal fraudulent financial communications.

Why malware is ruled out:

- No endpoint artifacts observed
- No exploit delivery evidence
- All activity occurred within cloud identity and email platforms

This aligns with common real-world BEC tradecraft relying on social engineering and identity abuse rather than technical exploitation.

---

## 9) Recommended Follow-Ups (Case Closure Actions)

The recommendations below summarize key containment, hardening, and detection priorities identified during this Business Email Compromise incident. These actions focus on reducing immediate risk related to identity abuse, mailbox manipulation, and fraudulent financial workflows.

Detailed technical controls, monitoring logic, and configuration-level guidance are documented separately in the dedicated recommendations report: `detection-and-hardening-recommendations.md`

This section is intended to highlight high-impact and time-sensitive actions for incident closure, while the supporting report provides implementation detail for security engineering, identity, and SOC teams.

#### ▶ 9.1) Immediate Containment

- Reset credentials and invalidate all active sessions
- Remove all inbox rules and attacker-created folders
- Suspend financial approvals pending verification

#### ▶ 9.2) Hardening

- Enforce MFA for all executive and finance users
- Restrict or monitor inbox rule creation
- Require out-of-band verification for financial approvals

#### ▶ 9.3) Detection

- Alert on inbox rule creation involving financial keywords
- Alert on folder creation followed by rule creation
- Correlate authentication + mailbox modification events

---

## 10) Supporting Reports (In This Folder)

The files below make up the full case package for this investigation and provide additional detail across analyst workflow, response actions, detection engineering, and executive-level reporting. Together, they support different audiences while maintaining a consistent incident record for this case.

- `investigation-walkthrough.md` — Step-by-step analyst workflow, tool usage, screenshots, and investigative pivots.
- `incident-summary.md` — Executive-level overview and business impact
- `incident-response-report.md` — Response actions and remediation steps
- `detection-artifact-report.md` — Log fields and detection pivots
- `detection-and-hardening-recommendations.md` — Preventive controls
- `MITRE-ATTACK-mapping.md` — Technique mapping with evidence references
- `images/` — All screenshots referenced as figures
- `README.md` — High-level overview of the investigation, environment, and lab objectives

---

## 11) MITRE ATT&CK Mapping

The mappings below provide a **high-level summary of confirmed adversary behaviors** observed during this incident and are intended as a quick reference for understanding the overall attack lifecycle.  

- For full investigative context and evidence-backed technique justification, see the detailed technique mapping embedded within the investigation walkthrough: `investigation-walkthrough.md`  
- A complete, standalone MITRE ATT&CK analysis — including expanded technique descriptions, detection considerations, and defensive gaps — is documented separately in: `MITRE-ATTACK-mapping.md`  

This structure reflects common incident response reporting practices, where case reports include summary mappings, while detailed technique analysis is maintained in supporting technical documentation.


#### ▶ 11.1) Technique Mapping

- Initial Access — Phishing (T1566): External impersonation email establishes financial trust relationship.
- Credential Access — Valid Accounts (T1078): Compromised credentials used for successful cloud authentication.
- Persistence — Mailbox Manipulation Rules (T1114.003): Inbox rules redirect and delete financial communications.
- Defense Evasion — Hide Artifacts (T1564): Concealment via hidden folder and automated suppression.
- Impact — Financial Fraud (T1657): Unauthorized transactions enabled through email workflow abuse.

#### ▶ 11.2) MITRE ATT&CK Mapping (Table View)

| Tactic | Technique | Description |
|------|-----------|-------------|
| Initial Access | **Phishing (T1566)** | Impersonation email posing as pension provider |
| Credential Access | **Valid Accounts (T1078)** | Successful `UserLoggedIn` events from attacker IPs |
| Persistence | **Email Collection: Mailbox Manipulation Rules (T1114.003)** | `New-InboxRule` filtering “withdrawal” |
| Defense Evasion | **Hide Artifacts (T1564)** | Routing to hidden folder `History` |

| Impact | **Financial Fraud (T1657)** | Fraudulent withdrawal approvals |
