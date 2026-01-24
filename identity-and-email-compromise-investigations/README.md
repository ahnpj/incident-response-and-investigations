# Identity and Email Compromise Investigations

This folder contains investigations where the **primary security failure involves unauthorized access to identities or misuse of email and messaging services**. These cases simulate how SOC analysts investigate account compromise, mailbox manipulation, and socially engineered financial workflows.

<blockquote>
**Note on categorization:** Investigations are grouped here based on the **primary attack surface and investigation focus (identity platforms and messaging services)**, not strictly by every tool or telemetry source involved. While supporting evidence may include endpoint or network artifacts, cases are categorized here when unauthorized access to accounts or mailbox functionality is the central security failure being investigated.
</blockquote>

Investigations in this category typically focus on:

- **Credential-based account compromise**, including suspicious authentication activity and abnormal access patterns.
- **Mailbox and messaging abuse**, such as inbox rule manipulation, forwarding, or suppression of sensitive communications.
- **Social engineering-driven fraud workflows**, where attackers leverage compromised identities to impersonate trusted users and initiate financial or data-exfiltration attempts.

Although these incidents may intersect with endpoint or application telemetry, they are organized here when the **core investigative surface is identity platforms or messaging systems rather than malware execution or web exploitation**.

---

## What’s in This Folder

Each investigation is contained in its **own dedicated folder** with full supporting documentation, including walkthroughs, case reports, artifact analysis, response reporting, defensive recommendations, and MITRE ATT&CK mapping.

Current investigations include:

- **Business Email Compromise (BEC) — Mailbox Rule Abuse and Account Takeover Investigation**  
  (`bec-mailbox-rule-abuse-investigation`)  
  Investigates how an attacker abuses Exchange inbox rules to hide financial communications after compromising executive credentials, validating unauthorized rule creation, identity access patterns, and the scope of mailbox manipulation.

---

## Investigation Documentation Structure

Each investigation in this folder is contained in its **own dedicated case folder** and includes supporting documents that reflect how identity- and email-driven incidents are handled in real SOC workflows.

Typical files include:

- **Investigation walkthrough (`investigation-walkthrough.md`)**  
  Step-by-step analyst actions showing how suspicious authentication activity and mailbox configuration changes were identified, validated, and correlated during the investigation.

- **Case report (`case-report.md`)**  
  Formal incident narrative describing how credentials were abused, what mailbox changes occurred, and how the attacker attempted to conceal activity or enable fraud.

- **Incident summary (`incident-summary.md`)**  
  Executive-level summary of the incident, including how it was detected, the business impact, and the investigation outcome.

- **Detection and artifact analysis (`detection-artifact-report.md`)**  
  Evidence-backed analysis of identity and mailbox artifacts such as sign-in logs, audit records, and rule configuration changes, including where each artifact was identified in the investigation.

- **Detection and hardening recommendations (`detection-and-hardening-recommendations.md`)**  
  Defensive improvements related to identity monitoring, mailbox protection, alerting on configuration changes, and user security controls.

- **Incident response report (`incident-response-report.md`)**  
  Containment and recovery considerations such as credential resets, MFA enforcement, mailbox rule cleanup, and post-incident monitoring.

- **MITRE ATT&CK mapping (`mitre-attack-mapping.md`)**  
  Evidence-backed mapping of observed behaviors to ATT&CK tactics and techniques tied directly to identity and mailbox abuse activities.

- **Screenshots and supporting evidence (`images/` or `screenshots/`)**  
  Visual documentation of authentication logs, mailbox rule configurations, and email artifacts referenced throughout the investigation.

Together, these documents separate **identity compromise validation**, **mailbox abuse analysis**, and **response planning** into clearly reviewable components tied to the same investigation narrative.

---

## Ongoing Development

Future investigations may expand into OAuth consent abuse, token theft, or collaboration platform phishing campaigns. As new cases are added, this category will continue to reflect how identity and messaging-based threats are investigated in real SOC environments.
