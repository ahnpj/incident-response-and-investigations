# Intrusion and Lateral Movement Investigations

This folder contains investigations where the **primary objective is to reconstruct attacker progression across multiple systems and network paths**. These cases simulate how SOC analysts trace intrusions beyond initial compromise to determine scope, affected systems, and attacker objectives using cross-host and network telemetry.

> **Note on categorization:**  
> Investigations are grouped here when the investigation centers on **multi-stage intrusion behavior and cross-host correlation**, not simply validating compromise on a single system. While endpoint and identity telemetry are often used, cases are categorized here when the core analytical challenge is **understanding how the attacker moved through the environment**.

Investigations in this category typically focus on:

- **Remote service exploitation or credential-based access** enabling movement between systems  
- **Lateral movement techniques**, including authentication abuse and network pivoting  
- **Kill-chain reconstruction**, correlating endpoint, authentication, and network telemetry to build full intrusion timelines  

Although individual hosts may exhibit malware or persistence mechanisms, investigations are organized here when the **primary goal is reconstructing multi-host attacker behavior rather than validating compromise on a single endpoint**.

---

## What’s in This Folder

Each investigation is contained in its **own dedicated folder** and represents **one complete intrusion scenario documented end-to-end**, including walkthroughs, reports, evidence, response actions, and defensive recommendations.

Current investigations include:

- **Windows Service Exploitation — Print Spooler Remote Code Execution (RCE) Investigation**  
  (`windows-print-spooler-rce-investigation`)  
  Examines exploitation of the Windows Print Spooler service leading to remote code execution and elevated privileges on a server, validated using host and network telemetry.

- **Intrusion Lifecycle Investigation — Lateral Movement Across Windows Hosts**  
  (`windows-intrusion-lifecycle-lateral-movement-investigation`)  
  Tracks attacker behavior from initial access through credential-based lateral movement, correlating firewall, authentication, and endpoint telemetry across multiple systems.

---

## Investigation Documentation Structure

Each investigation is fully self-contained in its own case folder and includes documentation aligned with how intrusion-focused incidents are handled in real SOC workflows.

| File / Folder | Purpose | Contents and Focus |
|--------|--------|--------------------|
| **`investigation-walkthrough.md`** | Intrusion reconstruction walkthrough | Chronological reconstruction of attacker activity across systems, including pivot logic and correlation steps |
| **`case-report.md`** | Formal incident narrative | How access was gained, how lateral movement occurred, and which systems were affected |
| **`incident-summary.md`** | Executive-level overview | High-level intrusion timeline, business impact, and final determination |
| **`detection-artifact-report.md`** | Evidence and detection analysis | Firewall logs, authentication records, endpoint telemetry, and cross-host correlation artifacts |
| **`detection-and-hardening-recommendations.md`** | Defensive improvements | Lateral movement detection, authentication monitoring, service exposure reduction, and network segmentation |
| **`incident-response-report.md`** | Remediation considerations | Host isolation, credential resets, service lockdown, and post-incident monitoring |
| **`mitre-attack-mapping.md`** | ATT&CK framework mapping | Evidence-backed mapping of each intrusion stage to ATT&CK techniques |
| **`images/` or `screenshots/`** | Validation artifacts | Visual evidence of cross-host activity, authentication pivots, and attacker movement paths |

Together, these documents support **multi-system investigation workflows** and emphasize correlation across diverse telemetry sources to reconstruct full intrusion lifecycles.

---

## Ongoing Development

Future investigations may expand into Active Directory attacks, pass-the-hash techniques, Kerberos abuse, or internal reconnaissance activity. New cases will continue to focus on tracing attacker movement and validating full intrusion scope using cross-domain telemetry.
