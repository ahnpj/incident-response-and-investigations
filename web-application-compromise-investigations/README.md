# Web Application Compromise Investigations

This folder contains investigations where the **primary attack surface is a web application or CMS platform**. These cases simulate how SOC analysts detect and validate exploitation of application-layer vulnerabilities and authentication workflows using HTTP and application telemetry.

> 👉 **Each folder represents one complete investigation**  
Every subfolder here is a **fully self-contained incident scenario**. Each one documents a single case from initial signal through validation, scoping, and response considerations.

> 👉 **Follow the investigation walkthrough first**  
Begin with `investigation-walkthrough.md` inside an investigation folder to see how I identified, pivoted on, and validated evidence step by step.

Investigations in this category typically focus on:

- **Authentication abuse**, including brute-force login attempts and credential-stuffing behavior  
- **Application exploitation**, such as file upload vulnerabilities enabling script deployment or web shell access  
- **Post-exploitation web activity**, including defacement or secondary payload delivery originating from compromised web servers  

Although later stages may involve host or network indicators, investigations are organized here when the **core investigative surface is the web application itself rather than endpoint or identity infrastructure**.

---

### What’s in This Folder

Each investigation is contained in its **own dedicated folder** and represents **one complete web compromise scenario documented end-to-end**, including walkthroughs, evidence analysis, response actions, and defensive recommendations.

Current investigations include:

- **Web Application Account Compromise — Brute-Force Authentication Abuse Investigation**  
  (`web-authentication-brute-force-account-compromise-investigation`)  
  Analyzes automated authentication attempts against a web login endpoint that result in successful account takeover, validated through application authentication telemetry and HTTP metadata.

- **Web Server Defacement — Malicious File Upload Exploitation Investigation**  
  (`web-server-defacement-malicious-file-upload-investigation`)  
  Investigates exploitation of vulnerable upload functionality leading to unauthorized script deployment and website defacement, corroborated by IDS, firewall, and host telemetry.

---

### Investigation Documentation Structure

Each investigation is fully self-contained in its own case folder and includes documentation aligned with how web-focused incidents are handled in operational SOC workflows.

| File / Folder | Purpose | Contents and Focus |
|--------|--------|--------------------|
| **`investigation-walkthrough.md`** | Exploitation and validation walkthrough | Step-by-step analysis of HTTP requests, authentication events, and application behavior used to confirm exploitation |
| **`case-report.md`** | Incident narrative | Vulnerability exploited, attacker actions, and impact to the web application |
| **`incident-summary.md`** | Executive overview | Business impact, exposure, and final investigation outcome |
| **`detection-artifact-report.md`** | Evidence and detection analysis | HTTP logs, IDS alerts, firewall events, and file artifacts supporting compromise confirmation |
| **`detection-and-hardening-recommendations.md`** | Defensive improvements | WAF tuning, authentication protections, logging enhancements, and application patching |
| **`incident-response-report.md`** | Remediation guidance | File cleanup, credential resets, vulnerability mitigation, and monitoring |
| **`mitre-attack-mapping.md`** | ATT&CK framework mapping | Exploitation and post-exploitation techniques mapped to ATT&CK using investigation evidence |
| **`images/` or `screenshots/`** | Validation artifacts | Visual proof of HTTP artifacts, IDS alerts, and application exploitation evidence |

Together, these documents demonstrate how **application-layer compromises are detected, validated, and remediated using correlated web, network, and host telemetry**.

---

### Ongoing Development

Future investigations may expand into API abuse, SQL injection, authentication bypass vulnerabilities, or cloud-hosted application misconfigurations. New cases will continue to reflect realistic web-based intrusion scenarios and operational investigation workflows.

