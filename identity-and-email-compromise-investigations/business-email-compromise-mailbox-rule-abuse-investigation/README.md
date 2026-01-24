# Business Email Compromise (BEC) Investigation (Malicious Mailbox Rule Abuse and Account Compromise)

**Category:** Identity and Email Compromise  
**Primary Attack Surface:** Microsoft 365 identity and mailbox configuration (Exchange Online rules)  
**Tactics Observed:** Initial Access, Persistence, Defense Evasion, Collection  
**Primary Data Sources:** Microsoft Entra ID (Azure AD) Sign-In Logs, Exchange Online Mailbox Audit Logs, Microsoft 365 Unified Audit Log (CSV export), Preserved Email Artifacts

---

### Overview

This investigation analyzes a Business Email Compromise (BEC) incident in which an executive mailbox was abused to authorize fraudulent pension withdrawals. The attack relied on valid credentials and manipulation of mailbox configuration rather than malware or endpoint exploitation.

The analysis focuses on reconstructing attacker behavior using Microsoft Entra ID (Azure AD) authentication telemetry and Exchange Online mailbox audit logs to identify how access was obtained, how financial correspondence was concealed, and how legitimate business processes were abused to enable fraud.

The investigation demonstrates how an analyst:
- Identifies unauthorized mailbox access using identity telemetry
- Detects malicious inbox rule creation and folder manipulation
- Correlates authentication events with mailbox configuration changes
- Reconstructs concealment techniques used to suppress financial emails

---

### What This Investigation Covers

This case simulates a real-world BEC scenario affecting a finance executive. Over a short time window, fraudulent transactions were processed after the attacker established trust through impersonation of a third-party pension provider, authenticated to the victim’s Microsoft 365 account using stolen credentials, created inbox rules to suppress or hide transaction-related emails, and diverted or deleted confirmation messages to delay detection.

The walkthrough explains why each data source was reviewed, how investigative pivots were chosen, and what evidence supports each conclusion. This mirrors how a SOC analyst would approach a post-incident financial fraud investigation using identity and mailbox telemetry rather than endpoint artifacts.

---

### How to Navigate This Investigation

This case is documented across multiple focused reports to reflect how incidents are handled in real SOC and incident response workflows. Supporting reports provide incident summaries, response actions, detection artifacts, and security improvement recommendations. A breakdown of each file is provided below.

If you want to follow the investigation step by step, start with:

**`investigation-walkthrough.md`**

---

### Repository Structure & Supporting Documents

All investigation outputs are intentionally separated into focused reports, similar to how SOC case management and incident response documentation is often organized in real environments.

| File / Folder | Purpose | Contents and Focus |
|-------------|--------|--------------------|
| `investigation-walkthrough.md` | Detailed analytical narrative reconstructing how the Business Email Compromise was carried out using identity and mailbox telemetry rather than endpoint-based indicators. | Documents review of Entra ID sign-in logs to identify anomalous authentication events and session context, correlation of successful logins with mailbox configuration changes in Exchange Online audit logs, identification of malicious inbox rule creation including rule conditions targeting financial workflow keywords, analysis of rule actions used to move or delete messages to suppress transaction-related communications, validation of hidden folder usage and mailbox manipulation designed to avoid user detection, and timeline reconstruction aligning mailbox changes with fraudulent financial activity. Explains why specific log sources were queried, how pivots were chosen, and how conclusions were derived strictly from observable cloud service telemetry. |
| `images/` | Visual evidence supporting analytical steps and conclusions documented in the reports. | Contains screenshots and log excerpts including Azure audit log entries, inbox rule configuration evidence, and preserved email artifacts with message header analysis used to validate investigative steps and conclusions. |
| `case-report.md` | Primary technical record of the investigation, aligned with SOC case documentation formats. | Summarizes incident background, scope of investigation, evidence sources, and final incident determination in a format used for incident tracking, escalation, and auditability. |
| `detection-artifact-report.md` | Detection-relevant technical artifacts derived from authentication and mailbox activity associated with the BEC incident. | Includes artifacts suitable for SIEM detections, alerting rules, and threat hunting queries, with emphasis on identity anomalies, mailbox rule manipulation patterns, and workflow abuse indicators that can support proactive detection of similar attacks. |
| `incident-response-report.md` | Operational response actions required to contain the incident, remediate affected accounts, and reduce risk of continued or repeat workflow abuse. | Covers containment steps, account remediation, communication considerations, and short-term monitoring recommendations reflecting how IR teams document tactical actions and immediate follow-up measures. |
| `incident-summary.md` | Executive-level overview written for stakeholders requiring situational awareness and business context without technical detail. | Summarizes what occurred, how business processes were affected, potential financial and reputational impact, and why the incident required security and operational response, intended for management, legal, compliance, and non-technical stakeholders. |
| `detection-and-hardening-recommendations.md` | Preventive controls and monitoring improvements identified through analysis of identity, authentication, and mailbox activity. | Includes recommendations covering identity protection and Conditional Access policy improvements, mailbox auditing and rule monitoring configurations, financial workflow verification controls outside of email, and logging/alerting gaps identified during the investigation. |
| `MITRE-ATT&CK-mapping.md` | Behavioral mapping of observed attacker behaviors to MITRE ATT&CK tactics and techniques using evidence from identity and mailbox telemetry. | Includes mapped techniques with specific evidence from this investigation, presented in both narrative form and a table view to support reporting, threat modeling, and alignment with detection and incident response frameworks. |

---

### Environment, Data Sources, and Tools

This investigation focuses on identity and email abuse within a cloud-hosted Microsoft 365 environment rather than endpoint-level malware or host compromise. All analysis was performed using cloud audit telemetry and preserved email artifacts associated with the compromised executive mailbox.

### Environment and Investigation Scope (At a Glance)

| Area | Details |
|------|---------|
| **Environment Type** | Cloud-hosted Microsoft 365 (identity and mailbox abuse; no endpoint compromise observed) |
| **Affected Assets** | Executive Entra ID identity and Exchange Online mailbox configuration (inbox rules) |
| **Victim Operating System** | Not applicable — compromise occurred within cloud-hosted Microsoft 365 services (identity and mailbox configuration), and no endpoint operating system compromise was observed |
| **Analyst Operating System** | Windows-based analyst workstation used for reviewing audit exports, inspecting preserved email artifacts, and performing log analysis |
| **Primary Platforms / Services** | Microsoft Entra ID (Azure AD), Microsoft Exchange Online, Microsoft 365 Unified Audit Logging |
| **Investigation Focus** | Credential-based mailbox access and concealment via malicious inbox rules tied to a financial/social-engineering workflow |

### Data Sources, Evidence, and Analysis Techniques

| Area | Details |
|------|---------|
| **Primary Telemetry Sources** | Azure AD Sign-In Logs; Azure AD/Microsoft 365 Audit Logs (CSV export); Exchange Online mailbox audit events and rule configuration records; preserved email artifacts associated with the pension withdrawal workflow |
| **Identity and Session Evidence** | Successful authentication events, source IP addresses, and timestamps used to validate credential-based access and correlate logins to mailbox manipulation |
| **Mailbox Rule Evidence** | Inbox rule creation and modification events, rule conditions (keyword filtering), and rule actions (message deletion, folder redirection, suppression) used to conceal transaction-related communications |
| **Email Artifact Evidence** | Preserved message artifacts reviewed for impersonated identities, approval language and social engineering techniques, and embedded banking/transaction metadata; headers and routing details used to validate sender behavior |
| **Azure Portal Usage** | Review of sign-in activity, audit events, and mailbox configuration changes directly within Microsoft 365 administrative interfaces |
| **VS Code Usage** | Searching and filtering large CSV audit exports, inspecting embedded JSON fields, and isolating high-signal authentication and mailbox-rule events |
| **PowerShell Usage** | Filtering audit records by operation and user, extracting rule configuration details, and correlating timestamps between authentication activity and mailbox manipulation events |
| **Thunderbird Usage** | Forensic-style review of preserved emails including full headers, sender routing information, and original MIME content for validation of impersonation techniques |
| **Operational Workflow Context** | Demonstrates how mailbox-based fraud can be detected and reconstructed using cloud audit telemetry and preserved email evidence in the absence of malware or endpoint compromise |

Each tool was selected to reflect common SOC and incident response workflows when investigating Business Email Compromise using cloud audit telemetry and preserved email evidence rather than endpoint-based artifacts.

---

### Intended Use

This investigation demonstrates structured identity and mailbox telemetry analysis for a financial fraud scenario. It reflects how credential-based access and mailbox manipulation are validated, documented, and translated into containment actions and longer-term detection and hardening improvements.

---

### Relevance to Security Operations

Business Email Compromise remains one of the most financially damaging and difficult-to-detect attack types because it relies on legitimate credentials, trusted business processes, and subtle mailbox manipulation rather than malware.

This investigation demonstrates how identity and mailbox audit telemetry can reveal initial access, persistence mechanisms through configuration abuse, attacker intent, and opportunities for earlier detection in cloud-first environments where endpoint artifacts may be minimal or irrelevant.

---

If you are reviewing this as part of my cybersecurity portfolio: this investigation is intended to demonstrate structured analytical thinking, evidence correlation across cloud telemetry sources, and professional incident documentation aligned with real operational workflows.
