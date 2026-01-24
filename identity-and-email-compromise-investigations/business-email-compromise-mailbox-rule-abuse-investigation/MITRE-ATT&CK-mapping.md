# MITRE ATT&CK Mapping - Business Email Compromise (BEC) Investigation (Malicious Mailbox Rule Abuse and Account Compromise)

This document maps attacker behaviors observed during this investigation to MITRE ATT&CK tactics and techniques using direct evidence from Microsoft Entra ID authentication telemetry, Exchange Online mailbox audit logs, and email message artifacts.

All mappings are based on confirmed activity identified during analysis rather than inferred attacker intent or assumed tooling.

The purpose of this mapping is to support standardized incident classification, detection coverage validation, and alignment with threat modeling frameworks commonly used by security operations teams.

---

## How This Mapping Was Performed

Techniques were mapped by reviewing:

- Authentication events identified during initial identity review  
- Mailbox configuration changes extracted from Exchange Online audit logs  
- Inbox rule parameters and actions observed during mailbox inspection  
- Email message headers and message body content related to financial workflows  

Each technique below references the specific behaviors and investigative pivots that supported the classification.

---

## MITRE ATT&CK Mapping (Narrative View)

### Initial Access

#### Phishing (T1566)

**Observed Behavior**  
Email communication impersonating a legitimate pension service provider was used to initiate a fraudulent financial workflow with the executive user.

During the walkthrough, this was identified when reviewing message headers and sender domains associated with withdrawal approval emails, which originated from external infrastructure but referenced valid business processes.

**Evidence Sources**  
- Email message artifacts reviewed during mailbox analysis  
- Message header fields identifying external sending domains  
- Transaction-related email content establishing business legitimacy

**Why This Maps to ATT&CK**  
The attacker relied on social engineering via email to establish trust and trigger business actions rather than exploiting technical vulnerabilities, which aligns with ATT&CK’s definition of phishing as an initial access technique.


### Credential Access

#### Valid Accounts (T1078)

**Observed Behavior**  
The compromised executive mailbox was accessed using valid credentials, with successful authentication events preceding mailbox configuration changes.

During the investigation, authentication events were reviewed in Entra ID audit logs and correlated with subsequent `New-InboxRule` operations in Exchange Online logs occurring within the same timeframe.

**Evidence Sources**  
- Entra ID sign-in logs showing successful authentication events for the victim account  
- Source IP addresses not previously associated with normal user activity  
- Temporal correlation between sign-in events and mailbox rule creation

**Why This Maps to ATT&CK**  
Use of legitimate credentials to access cloud services matches ATT&CK’s Valid Accounts technique, which covers abuse of authorized access rather than technical exploitation.


### Persistence

#### Email Collection: Mailbox Manipulation Rules (T1114.003)

**Observed Behavior**  
Inbox rules were created to automatically process incoming financial correspondence without user visibility.

Rule configuration review revealed conditions matching transaction-related keywords and actions configured to move or delete messages before reaching the inbox.

**Evidence Sources**  
- Exchange Online audit logs showing `New-InboxRule` operations  
- Rule condition fields such as `BodyContainsWords` and `SubjectContainsWords`  
- Rule actions including `MoveToFolder` and `DeleteMessage`  
- Rule execution timestamps following authentication events

**Why This Maps to ATT&CK**  
Mailbox rule abuse is explicitly documented in ATT&CK as a persistence technique for email collection and traffic manipulation, allowing attackers to maintain control over information flow even after initial access.


### Defense Evasion

#### Hide Artifacts (T1564)

**Observed Behavior**  
Inbox rules were configured to suppress financial communications by redirecting or deleting messages before the victim could view them.

During rule inspection, actions were observed that both removed messages from the inbox and prevented subsequent rule processing, ensuring financial alerts remained concealed.

**Evidence Sources**  
- Rule parameters including `DeleteMessage=True` and `StopProcessingRules=True`  
- Folder routing to non-default mailbox locations  
- Absence of financial notifications in user-visible mailbox views

**Why This Maps to ATT&CK**  
The attacker deliberately concealed evidence of fraudulent activity from the victim by manipulating visibility of artifacts, which aligns with ATT&CK techniques focused on hiding evidence to avoid detection.


### Impact

#### Financial Fraud (T1657)

**Observed Behavior**  
Unauthorized pension withdrawal transactions were approved using the compromised executive mailbox after message suppression mechanisms were established.

Timeline reconstruction showed that mailbox rule creation occurred prior to the approval of fraudulent transactions, indicating control of the email workflow enabled the financial impact.

**Evidence Sources**  
- Email communications approving withdrawals  
- Financial workflow correspondence timestamps  
- Correlation between mailbox manipulation and transaction authorization events

**Why This Maps to ATT&CK**  
The attacker’s actions directly enabled unauthorized financial transactions, matching ATT&CK’s Financial Fraud impact technique, which covers monetary theft facilitated through compromised access.

---

## MITRE ATT&CK Mapping (Table View)

| Tactic | Technique ID | Technique Name | Evidence Summary | Evidence Source |
|--------|--------------|----------------|------------------|-----------------|
| Initial Access | T1566 | Phishing | External email impersonating pension provider initiated fraudulent workflow | Email artifacts, headers |
| Credential Access | T1078 | Valid Accounts | Successful login using compromised executive credentials prior to mailbox changes | Entra ID sign-in logs |
| Persistence | T1114.003 | Mailbox Manipulation Rules | Inbox rules created to redirect or delete finance-related emails | Exchange audit logs |
| Defense Evasion | T1564 | Hide Artifacts | Message suppression using delete and hidden-folder routing rules | Inbox rule configuration |
| Impact | T1657 | Financial Fraud | Fraudulent pension withdrawals approved using compromised mailbox | Email evidence, transaction context |

This table provides a condensed reference suitable for reporting, detection validation, and technique tracking across multiple incidents.

---

## Detection and Control Relevance

Mapping behaviors to MITRE ATT&CK supports defensive operations by:

- Highlighting the need for monitoring of mailbox rule creation for high-risk users  
- Reinforcing the importance of correlating authentication events with configuration changes  
- Identifying gaps where financial workflows rely solely on email-based approvals  

Detection opportunities and preventive control recommendations associated with these techniques are documented in:

- `detection-artifact-report.md`  
- `detection-and-hardening-recommendations.md`

---

## Notes and Assumptions

- Techniques are mapped solely based on behaviors confirmed in logs and email artifacts reviewed during this investigation.
- No malware delivery, exploit activity, or endpoint compromise was observed within the scope of available telemetry.
- Techniques were selected to represent the primary behaviors that enabled the incident while avoiding unnecessary over-classification.

This mapping reflects how ATT&CK is commonly applied during Business Email Compromise investigations in cloud-based enterprise environments.
