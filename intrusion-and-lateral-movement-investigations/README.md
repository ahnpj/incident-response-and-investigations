# Intrusion and Lateral Movement Investigations

This folder contains investigations where the **primary objective is to reconstruct attacker progression across multiple systems and network paths**. These cases simulate how SOC analysts track intrusions beyond initial compromise to understand scope, impact, and attacker objectives.

<blockquote>
**Note on categorization:** Investigations are grouped here based on the goal of **reconstructing attacker movement across systems and network paths**, not simply validating compromise on a single host. While endpoint and identity logs are heavily used, cases are categorized here when the investigation centers on **multi-stage intrusion behavior and cross-host correlation**.
</blockquote>

Investigations in this category typically focus on:

- **Remote service exploitation or credential-based access**, enabling attackers to move between systems.
- **Lateral movement techniques**, including authentication abuse and network pivoting.
- **Kill-chain reconstruction**, correlating endpoint, authentication, and network telemetry to understand how the attack unfolded.

Although individual hosts may exhibit malware or persistence mechanisms, investigations are organized here when the **core challenge is understanding multi-host intrusion behavior and attacker movement through the environment**.

---

## What’s in This Folder

Each investigation is contained in its **own dedicated folder** with full supporting documentation, including walkthroughs, case reports, artifact analysis, response reporting, defensive recommendations, and MITRE ATT&CK mapping.

Current investigations include:

- **Windows Service Exploitation — Print Spooler Remote Code Execution (RCE) Investigation**  
  (`windows-print-spooler-rce-investigation`)  
  Examines exploitation of the Windows Print Spooler service leading to remote code execution and elevated privileges on a server, including validation using host and network telemetry.

- **Intrusion Lifecycle Investigation — Lateral Movement Across Windows Hosts**  
  (`windows-intrusion-lifecycle-lateral-movement-investigation`)  
  Tracks attacker behavior from initial access through credential-based lateral movement, correlating firewall, authentication, and endpoint telemetry across multiple systems.

---

## Investigation Documentation Structure

Each investigation in this folder is contained in its **own dedicated case folder** and includes supporting documents that reflect how intrusion-focused incidents are handled in real SOC workflows.

Typical files include:

- **Investigation walkthrough (`investigation-walkthrough.md`)**  
  Chronological reconstruction of attacker activity across systems, including pivot logic and correlation steps.

- **Case report (`case-report.md`)**  
  Incident narrative describing how access was gained, how movement occurred, and what systems were affected.

- **Incident summary (`incident-summary.md`)**  
  Executive-level summary outlining the intrusion timeline and overall impact.

- **Detection and artifact analysis (`detection-artifact-report.md`)**  
  Detailed review of firewall logs, authentication records, endpoint telemetry, and other artifacts used to validate movement.

- **Detection and hardening recommendations (`detection-and-hardening-recommendations.md`)**  
  Defensive improvements related to lateral movement detection, authentication monitoring, and network segmentation.

- **Incident response report (`incident-response-report.md`)**  
  Containment and recovery considerations such as isolating hosts, resetting credentials, and blocking exploited services.

- **MITRE ATT&CK mapping (`mitre-attack-mapping.md`)**  
  ATT&CK techniques mapped to each stage of the intrusion lifecycle using evidence from the investigation.

- **Screenshots and supporting evidence (`images/` or `screenshots/`)**  
  Visual evidence showing cross-host correlations and attacker movement paths.

Together, these documents support **multi-system investigation workflows** and emphasize correlation across diverse telemetry sources.

---

## Ongoing Development

Future investigations may expand into Active Directory attacks, pass-the-hash techniques, or internal reconnaissance activity. New cases will continue to focus on tracing attacker movement and understanding full intrusion scope.
