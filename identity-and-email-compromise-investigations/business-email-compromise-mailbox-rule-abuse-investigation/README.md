# Business Email Compromise (BEC) Investigation (Malicious Mailbox Rule Abuse and Account Compromise)

**Category:** Endpoint Compromise and Persistence  
**Primary Attack Surface:** Local host execution environment  
**Tactics Observed:** Execution, Persistence, Resource Hijacking, Defense Evasion  
**Primary Data Sources:** Windows Security Event Logs, Sysmon Process Creation Events

This investigation analyzes a Business Email Compromise (BEC) incident in which an executive mailbox was abused to authorize fraudulent pension withdrawals. The attack relied on valid credentials and manipulation of mailbox configuration rather than malware or endpoint exploitation.

The analysis focuses on reconstructing attacker behavior using Microsoft Entra ID (Azure AD) authentication telemetry and Exchange Online mailbox audit logs to identify how access was obtained, how financial correspondence was concealed, and how legitimate business processes were abused to enable fraud.

The investigation demonstrates how an analyst:
- Identifies unauthorized mailbox access using identity telemetry
- Detects malicious inbox rule creation and folder manipulation
- Correlates authentication events with mailbox configuration changes
- Reconstructs concealment techniques used to suppress financial emails

---

## What This Investigation Covers

This case simulates a real-world BEC scenario affecting a finance executive. Over a short time window, fraudulent transactions were processed after the attacker:

- Established trust through impersonation of a third-party pension provider  
- Authenticated to the victim’s Microsoft 365 account using stolen credentials  
- Created inbox rules to suppress or hide transaction-related emails  
- Diverted or deleted confirmation messages to delay detection  

The walkthrough explains:

- **Why each data source was reviewed**
- **How investigative pivots were chosen**
- **What evidence supports each conclusion**

This mirrors how a SOC analyst would approach a post-incident financial fraud investigation.

---

## Environment, Data Sources, and Tools

This investigation focuses on identity and email abuse within a cloud-hosted Microsoft 365 environment rather than endpoint-level malware or host compromise. All analysis was performed using cloud audit telemetry and preserved email artifacts associated with the compromised executive mailbox.

### At-a-Glance Summary

| Area | Details |
|------|---------|
| **Environment Type** | Cloud-hosted Microsoft 365 (identity + mailbox abuse; no endpoint compromise observed) |
| **Affected Assets** | Executive Entra ID identity and Exchange Online mailbox configuration (inbox rules) |
| **Primary Platforms / Services** | Microsoft Entra ID (Azure AD), Microsoft Exchange Online, Microsoft 365 Unified Audit Logging |
| **Telemetry Sources Reviewed** | Azure AD Sign-In Logs; Azure AD / Microsoft 365 Audit Logs (CSV export); mailbox rule configuration records |
| **Evidence Types** | Sign-in activity + source IP/timestamps; rule creation/modification metadata; preserved pension-withdrawal phishing email artifacts |
| **Tools Used** | Azure Portal; Visual Studio Code (CSV/JSON review + filtering); PowerShell (audit/export handling + correlation); Thunderbird (full header + MIME review) |
| **Investigation Focus** | Credential-based mailbox access + concealment via malicious inbox rules tied to a financial/social-engineering workflow |

### Operating Systems

- **Affected System (Victim Environment):**  
  Not applicable — the compromise occurred within cloud-hosted Microsoft 365 services (identity and mailbox configuration), and no endpoint operating system compromise was observed.

- **Analyst Environment:**  
  Windows-based analyst workstation used for reviewing audit exports, inspecting email artifacts, and performing log analysis.

### Platforms and Services

- **Microsoft Entra ID (Azure Active Directory)**  
  Used to analyze authentication activity associated with the compromised executive account, including successful sign-ins, source IP addresses, and timestamps used to validate credential-based access.

- **Microsoft Exchange Online**  
  Used to investigate mailbox configuration changes, specifically inbox rule creation and modification used to suppress withdrawal-related communications.

- **Microsoft 365 Unified Audit Logging**  
  Provided mailbox rule creation events and configuration details exported for offline analysis.

### Data Sources Reviewed

- **Azure AD Sign-In Logs**  
  Reviewed to identify:
  - Successful authentication events for the compromised account
  - Source IP addresses associated with suspicious access
  - Temporal correlation between logins and mailbox rule creation

- **Azure AD / Microsoft 365 Audit Logs (CSV Export)**  
  Reviewed to identify:
  - Inbox rule creation and modification events
  - Rule conditions such as keyword filtering
  - Rule actions including message deletion and folder redirection

- **Email Message Artifacts Related to the Pension Withdrawal Workflow**  
  Examined to analyze:
  - Impersonated sender identities
  - Approval language and social engineering techniques
  - Embedded banking and transaction metadata

- **Mailbox Rule Configuration Records**  
  Reviewed to validate concealment techniques, including:
  - Keyword-based filtering (e.g., financial terminology)
  - Message deletion and suppression behavior
  - Routing of emails to attacker-controlled folders

### Tools and Analysis Techniques

- **Azure Portal**  
  Used to review identity sign-in activity, audit events, and mailbox configuration changes directly within Microsoft 365 administrative interfaces.

- **Visual Studio Code**  
  Used to search and filter large CSV audit log exports, inspect embedded JSON fields, and isolate high-signal mailbox rule and authentication records.

- **PowerShell**  
  Used to:
  - Filter audit log records by operation type and user
  - Extract rule configuration details
  - Correlate timestamps between authentication and mailbox manipulation events

- **Thunderbird (Email Client)**  
  Used for forensic-style review of preserved email artifacts, including:
  - Full message headers
  - Sender routing information
  - Original MIME content for validation of impersonation techniques

Each tool was selected to reflect common SOC and incident response workflows when investigating Business Email Compromise using cloud audit telemetry and preserved email evidence rather than endpoint-based malware artifacts.

---

## Repository Structure & Supporting Documents

All investigation outputs are intentionally separated into focused reports, similar to how SOC case management and incident response documentation is often organized in real environments.

### `investigation-walkthrough.md`

Provides a detailed analytical narrative reconstructing how the Business Email Compromise was carried out using identity and mailbox telemetry rather than endpoint-based indicators.

The walkthrough documents:

- Review of Entra ID (Azure AD) sign-in logs to identify anomalous authentication events and session context  
- Correlation of successful logins with mailbox configuration changes in Exchange Online audit logs  
- Identification of malicious inbox rule creation, including rule conditions targeting financial workflow keywords  
- Analysis of rule actions used to move or delete messages to suppress transaction-related communications  
- Validation of hidden folder usage and mailbox manipulation designed to avoid user detection  
- Timeline reconstruction showing how mailbox changes aligned with fraudulent financial activity  

Each step explains why specific log sources were queried, how investigative pivots were chosen, and how conclusions were drawn strictly from observable cloud service telemetry, demonstrating how mailbox-based fraud can be detected even in the absence of malware or endpoint compromise.


### `images`

Contains all screenshots and log excerpts referenced throughout the investigation, including:

- Azure audit log entries  
- Inbox rule configuration evidence  
- Email artifacts and message header analysis  

These images provide visual validation of investigative steps, support written conclusions, and demonstrate how evidence was verified directly from source telemetry.


### `case-report.md`

Provides the primary technical record of the investigation, documenting how the incident was analyzed, what evidence was reviewed, and how conclusions were reached.

Summarizes:

- Incident background  
- Scope of investigation  
- Evidence sources  
- Final incident determination  

This file is written in the style of formal case documentation used in security operations and ticketing systems for incident tracking, escalation, and auditability.


### `detection-artifact-report.md`

Documents detection-relevant technical artifacts derived from authentication and mailbox activity associated with the BEC incident, with focus on behaviors that can be operationalized in monitoring and alerting systems.

Includes artifacts suitable for:

- SIEM detections  
- Alerting rules  
- Threat hunting queries  

Emphasis is placed on identity anomalies, mailbox rule manipulation patterns, and workflow abuse indicators that can support proactive detection of similar attacks in the future.


### `incident-response-report.md`

Focuses on operational response actions required to contain the incident, remediate affected accounts, and reduce the risk of continued or repeat abuse of business workflows.

Includes:

- Containment steps  
- Account remediation  
- Communication considerations  
- Short-term monitoring recommendations  

This file reflects how incident response teams document tactical actions taken during active incidents and outline immediate follow-up measures to stabilize affected systems.


### `incident-summary.md`

Provides a concise executive-level overview of the incident, written for stakeholders who require situational awareness and business context without needing technical investigation details.

Intended for:

- Management  
- Legal  
- Compliance  
- Non-technical stakeholders  

Summarizes what occurred, how business processes were affected, potential financial and reputational impact, and why the incident required security and operational response.


### `detection-and-hardening-recommendations.md`

Focuses on preventive controls and monitoring improvements identified through analysis of identity, authentication, and mailbox activity associated with the BEC incident, with emphasis on reducing both the likelihood of credential-based access and the impact of mailbox configuration abuse.

Includes recommendations covering:

- Identity protection and Conditional Access policy recommendations  
- Mailbox auditing and rule monitoring configurations  
- Financial workflow verification controls outside of email  
- Logging and alerting gaps identified during the investigation  

This file reflects how security teams document post-incident hardening actions and detection improvements to reduce the likelihood and impact of future attacks.


### `MITRE-ATT&CK-mapping.md`

Maps observed attacker behaviors to MITRE ATT&CK tactics and techniques using evidence directly extracted from identity and mailbox telemetry, enabling standardized classification of the intrusion across recognized adversary tradecraft categories.

Includes:

- MITRE ATT&CK tactics and techniques  
- Specific evidence from this investigation  

Both narrative explanations and a table view are provided to support reporting, threat modeling, and alignment with detection and incident response frameworks.

---

## Who This Lab Is For

This investigation is designed for:

- Aspiring SOC analysts
- Blue-team practitioners building cloud investigation skills
- Anyone learning how BEC incidents are handled operationally

It emphasizes:

- Cloud log analysis over malware analysis
- Evidence-based conclusions
- Realistic SOC documentation formats

---

## Why This Matters for Security Operations

Business Email Compromise remains one of the most financially damaging and difficult-to-detect attack types because it relies on:

- Legitimate credentials
- Trusted business processes
- Subtle mailbox manipulation rather than noisy malware

This lab demonstrates how even minimal telemetry — when analyzed correctly — can reveal:

- Initial access
- Persistence mechanisms
- Attacker intent
- Opportunities for earlier detection

Understanding these patterns is critical for modern SOC teams operating in cloud-first environments.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation is intended to demonstrate not just tool usage, but structured analytical thinking, evidence correlation, and professional-style incident documentation.