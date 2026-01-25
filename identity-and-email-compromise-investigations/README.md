# Identity and Email Compromise Investigations

This folder contains investigations where the **primary security failure involves unauthorized access to identities or misuse of email and messaging services**. These cases simulate how SOC analysts investigate account compromise, mailbox manipulation, and socially engineered financial or data-exfiltration workflows using identity and messaging telemetry.

> **Note on categorization:**  
> Investigations are grouped here when **identity platforms and messaging services are the primary attack surface and investigation focus**, not strictly based on every tool or telemetry source involved. While supporting evidence may include endpoint or network artifacts, cases are categorized here when **unauthorized access to accounts or mailbox functionality is the central security failure being investigated**.

Investigations in this category typically focus on:

- **Credential-based account compromise**, including anomalous sign-in activity and abnormal access patterns  
- **Mailbox and messaging abuse**, such as inbox rule manipulation, forwarding, and suppression of sensitive communications  
- **Social-engineering-driven fraud workflows**, where attackers impersonate trusted users to initiate financial or data-access actions  

Although these incidents may intersect with endpoint or application telemetry, they are organized here when the **core investigative surface is identity and messaging systems rather than malware execution or web exploitation**.

---

### What’s in This Folder

Each investigation is contained in its **own dedicated folder** and represents **one complete incident scenario documented end-to-end**, including walkthroughs, reports, artifacts, response actions, and defensive recommendations.

Current investigations include:

- **Business Email Compromise (BEC) — Mailbox Rule Abuse and Account Takeover Investigation**  
  (`business-email-compromise-mailbox-rule-abuse-investigation`)  
  Examines how an attacker abuses Exchange inbox rules to conceal financial communications after credential compromise, validating unauthorized rule creation, identity access patterns, and the scope of mailbox manipulation.

---

### Investigation Documentation Structure

Each investigation is fully self-contained in its own case folder and includes documentation aligned with how identity- and email-driven incidents are handled in real SOC workflows.

| File / Folder | Purpose | Contents and Focus |
|--------|--------|--------------------|
| **`investigation-walkthrough.md`** | Analyst workflow and validation steps | Step-by-step actions showing how suspicious authentication activity and mailbox configuration changes were identified, validated, and correlated |
| **`case-report.md`** | Formal incident narrative | How credentials were abused, what mailbox changes occurred, and how the attacker attempted to conceal activity or enable fraud |
| **`incident-summary.md`** | Executive-level overview | Detection method, business impact, and final investigative outcome |
| **`detection-artifact-report.md`** | Evidence and detection analysis | Identity logs, mailbox audit records, and configuration changes with evidence-backed conclusions |
| **`detection-and-hardening-recommendations.md`** | Defensive improvements | Identity monitoring, mailbox protection, alerting on configuration changes, and control enhancements |
| **`incident-response-report.md`** | Remediation considerations | Credential resets, MFA enforcement, mailbox rule cleanup, and post-incident monitoring |
| **`mitre-attack-mapping.md`** | ATT&CK framework mapping | Evidence-backed mapping of identity and mailbox abuse behaviors to ATT&CK techniques |
| **`images/` or `screenshots/`** | Validation artifacts | Authentication logs, mailbox rule screenshots, and supporting visual evidence |

Together, these documents separate **identity compromise validation**, **mailbox abuse analysis**, and **response planning** into clearly reviewable components tied to the same incident narrative.

---

### Ongoing Development

Future investigations may expand into OAuth consent abuse, token theft, session hijacking, or collaboration-platform phishing campaigns. New cases will continue to reflect how identity and messaging-based threats are investigated in operational SOC environments.

