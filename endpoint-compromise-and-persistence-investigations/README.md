# Endpoint Compromise and Persistence Investigations

This folder contains investigations where the **primary detection surface and evidence source is host-level telemetry** from Windows endpoints. These cases simulate how SOC analysts identify, validate, and scope suspicious activity occurring directly on compromised systems.

> **Note on categorization:**
> Investigations are grouped here based on **host-level compromise and persistence mechanisms** being the primary investigation focus, not solely on how the attacker initially gained access. Even when phishing, exploitation, or lateral movement precedes the activity, cases are categorized here when **endpoint telemetry and local artifacts drive detection and validation**.

</blockquote>

Investigations in this category typically focus on:

- **Malware execution and suspicious process behavior**, including binaries launched from abnormal locations or using suspicious command-line arguments.
- **Persistence mechanisms**, such as registry autorun keys, scheduled tasks, service abuse, or unauthorized account creation used to maintain long-term access.
- **Post-exploitation host activity**, where attackers leverage built-in system tools (Living-off-the-Land techniques) to blend into normal administrative behavior.

Although initial access may occur through phishing, exploitation, or lateral movement, cases are organized here when the **core investigation relies on endpoint logs and host artifacts to validate compromise and persistence**.

---

## What’s in This Folder

Each investigation is contained in its **own dedicated folder** with full supporting documentation, including walkthroughs, case reports, artifact analysis, response reporting, defensive recommendations, and MITRE ATT&CK mapping.

Current investigations include:

- **Endpoint Cryptominer Infection — Suspicious Process Execution Investigation**  
  (`endpoint-cryptominer-suspicious-process-investigation`)  
  Focuses on detecting abnormal process execution patterns consistent with cryptomining malware, validating suspicious binaries, and confirming malicious behavior using Windows process telemetry.

- **Windows Host Compromise — Backdoor Account and Registry Persistence Investigation**  
  (`windows-backdoor-account-registry-persistence-investigation`)  
  Documents unauthorized local account creation and registry-based autorun persistence mechanisms used to maintain long-term access to a compromised workstation.

- **Windows Malware Triage — Living-off-the-Land Binary (LoLBin) Abuse and Payload Validation Investigation**  
  (`windows-malware-triage-lolbin-validation-investigation`)  
  Validates suspicious payloads and persistence techniques by analyzing digital signatures, scheduled tasks, registry startup entries, and file reputation using threat intelligence services.

---

## Investigation Documentation Structure

Each investigation in this folder is contained in its **own dedicated case folder** and includes supporting documents that reflect how endpoint-focused incidents are handled in real SOC workflows.

Typical files include:

- **Investigation walkthrough (`investigation-walkthrough.md`)**  
  Step-by-step analyst actions and pivots used to identify malicious execution, validate persistence mechanisms, and correlate host artifacts during the investigation.

- **Case report (`case-report.md`)**  
  Formal narrative of the incident, including scope, investigation methodology, confirmed findings, and host-level compromise indicators.

- **Incident summary (`incident-summary.md`)**  
  Executive-level overview summarizing what occurred, how it was detected, and the final investigative outcome.

- **Detection and artifact analysis (`detection-artifact-report.md`)**  
  Detailed breakdown of process events, registry modifications, account changes, scheduled tasks, and file artifacts with evidence-based conclusions.

- **Detection and hardening recommendations (`detection-and-hardening-recommendations.md`)**  
  Defensive improvements related to endpoint monitoring, logging coverage, persistence detection, and system hardening.

- **Incident response report (`incident-response-report.md`)**  
  Containment and remediation considerations such as isolating hosts, removing persistence, and credential hygiene.

- **MITRE ATT&CK mapping (`mitre-attack-mapping.md`)**  
  Evidence-backed ATT&CK techniques mapped directly to host artifacts and investigation steps.

- **Screenshots and supporting evidence (`images/` or `screenshots/`)**  
  Visual documentation of logs, registry keys, scheduled tasks, and validation steps.

Together, these documents separate **host investigation workflow**, **artifact validation**, and **response considerations** into clearly reviewable components tied to the same incident narrative.

---

## Ongoing Development

Future investigations may expand into additional persistence mechanisms, credential dumping, or memory-based attacks. New cases will continue to reflect how endpoint compromise and post-exploitation behavior are investigated in operational SOC environments.

