# Web Application Compromise Investigations

This folder contains investigations where the **primary attack surface is a web application or CMS platform**. These cases simulate how SOC analysts detect and validate exploitation of application-layer vulnerabilities and authentication workflows.

<blockquote>
**Note on categorization:** Investigations are grouped here based on **application-layer attack surfaces and HTTP-driven exploitation**, not strictly by the downstream impact of the incident. Even when compromised accounts or host artifacts are involved, cases are categorized here when **web requests and application behavior are the primary detection and investigation surfaces**.
</blockquote>

Investigations in this category typically focus on:

- **Authentication abuse**, including brute-force login attempts and credential-stuffing behavior.
- **Application exploitation**, such as file upload vulnerabilities that enable script deployment or web shell access.
- **Post-exploitation web activity**, including defacement or secondary payload execution originating from compromised web servers.

Although these incidents may later involve host-level artifacts or network indicators, they are organized here when the **initial access vector and primary telemetry come from HTTP and application logs**.

---

## What’s in This Folder

Each investigation is contained in its **own dedicated folder** with full supporting documentation, including walkthroughs, case reports, artifact analysis, response reporting, defensive recommendations, and MITRE ATT&CK mapping.

Current investigations include:

- **Web Application Account Compromise — Brute-Force Authentication Abuse Investigation**  
  (`web-authentication-brute-force-account-compromise-investigation`)  
  Analyzes repeated authentication attempts against a web login endpoint that result in successful account takeover, validated through application authentication telemetry.

- **Web Server Defacement — Malicious File Upload Exploitation Investigation**  
  (`web-server-defacement-malicious-file-upload-investigation`)  
  Investigates exploitation of vulnerable upload functionality leading to unauthorized script deployment and website defacement, corroborated by IDS, firewall, and host telemetry.

---

## Investigation Documentation Structure

Each investigation in this folder is contained in its **own dedicated case folder** and includes supporting documents that reflect how web-focused incidents are handled in real SOC workflows.

Typical files include:

- **Investigation walkthrough (`investigation-walkthrough.md`)**  
  Step-by-step analysis of HTTP requests, authentication events, and application behavior used to confirm exploitation.

- **Case report (`case-report.md`)**  
  Narrative describing the vulnerability exploited, attacker actions, and impact to the web application.

- **Incident summary (`incident-summary.md`)**  
  Executive-level summary focused on business impact and exposure of the web service.

- **Detection and artifact analysis (`detection-artifact-report.md`)**  
  Detailed breakdown of HTTP logs, IDS alerts, firewall events, and file artifacts supporting compromise confirmation.

- **Detection and hardening recommendations (`detection-and-hardening-recommendations.md`)**  
  Defensive improvements such as WAF tuning, authentication protections, logging enhancements, and application patching.

- **Incident response report (`incident-response-report.md`)**  
  Containment and remediation considerations including file cleanup, credential resets, and vulnerability mitigation.

- **MITRE ATT&CK mapping (`mitre-attack-mapping.md`)**  
  ATT&CK techniques mapped to exploitation and post-exploitation behaviors validated during investigation.

- **Screenshots and supporting evidence (`images/` or `screenshots/`)**  
  Visual proof of HTTP artifacts, IDS alerts, and application-level exploitation evidence.

Together, these documents reflect how **application-layer compromises are investigated and validated in operational SOC environments**.

---

## Ongoing Development

Future investigations may expand into API abuse, SQL injection, or authentication bypass vulnerabilities. New cases will continue to reflect realistic web-based intrusion scenarios.
