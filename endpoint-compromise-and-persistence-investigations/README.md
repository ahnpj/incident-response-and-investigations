# Endpoint Compromise and Persistence Investigations

This folder contains investigations where the **primary detection surface and evidence source is host-level telemetry from Windows endpoints**. These cases simulate how SOC analysts identify, validate, and scope suspicious activity occurring directly on compromised systems using endpoint logs and local artifacts.

> 👉 **Each folder represents one complete investigation**  
Every subfolder here is a **fully self-contained incident scenario**. Each one documents a single case from initial signal through validation, scoping, and response considerations.

> 👉 **Follow the investigation walkthrough first**  
Begin with `investigation-walkthrough.md` inside an investigation folder to see how I identified, pivoted on, and validated evidence step by step.

<!--
> **Note on categorization:**  
> Investigations are grouped here when **host-level compromise and persistence mechanisms are the primary investigation focus**, not solely based on how the attacker initially gained access. Even if phishing, exploitation, or lateral movement precedes the activity, cases are categorized here when **endpoint telemetry and local artifacts drive detection, validation, and scoping**.
-->

Although initial access may occur elsewhere, cases are organized here when the **core investigation relies on endpoint logs and host artifacts to confirm compromise and persistence**.

---

### What’s in This Folder

Each investigation is contained in its **own dedicated folder** and represents **one complete incident scenario documented end-to-end**, including walkthroughs, reports, artifacts, and defensive recommendations.

Current investigations include:

- **Endpoint Cryptominer Infection — Suspicious Process Execution Investigation**  
  (`endpoint-cryptominer-suspicious-process-investigation`)  
  Detects abnormal execution patterns consistent with cryptomining malware, validates suspicious binaries, and confirms malicious behavior using Windows process telemetry.

- **Windows Host Compromise — Backdoor Account and Registry Persistence Investigation**  
  (`windows-backdoor-account-registry-persistence-investigation`)  
  Documents unauthorized local account creation and registry-based autorun persistence mechanisms used to maintain long-term access.

- **Windows Malware Triage — Living-off-the-Land Binary (LoLBin) Abuse and Payload Validation Investigation**  
  (`windows-malware-triage-lolbin-validation-investigation`)  
  Validates suspicious payloads and persistence techniques using digital signatures, scheduled tasks, registry startup entries, and file reputation via threat intelligence services.

---

### Investigation Documentation Structure

Each investigation is fully self-contained in its own case folder and includes documentation aligned with how endpoint-focused incidents are handled in real SOC workflows.

| File / Folder | Purpose | Contents and Focus |
|--------|--------|--------------------|
| **`investigation-walkthrough.md`** | Analyst workflow and validation steps | Step-by-step actions used to identify malicious execution, validate persistence mechanisms, and correlate host artifacts |
| **`case-report.md`** | Formal incident narrative | Scope, investigation methodology, confirmed findings, and host-level compromise indicators |
| **`incident-summary.md`** | Executive-level overview | What occurred, how it was detected, and final investigative outcome |
| **`detection-artifact-report.md`** | Evidence and detection analysis | Detailed breakdown of process events, registry changes, account activity, scheduled tasks, and file artifacts |
| **`detection-and-hardening-recommendations.md`** | Defensive improvements | Endpoint monitoring gaps, persistence detection opportunities, and system hardening guidance |
| **`incident-response-report.md`** | Remediation considerations | Host isolation, persistence removal, credential hygiene, and recovery actions |
| **`mitre-attack-mapping.md`** | ATT&CK framework mapping | Evidence-backed mapping of observed behaviors to ATT&CK techniques tied to investigation steps |
| **`images/` or `screenshots/`** | Validation artifacts | Log excerpts, registry views, task listings, and supporting visual evidence |

Together, these files separate **host investigation workflow**, **artifact validation**, and **response planning** into clearly reviewable components while remaining tied to the same incident narrative.

---

### Ongoing Development

Future investigations may expand into additional persistence techniques, credential dumping, or memory-based attacks. New cases will continue to reflect how endpoint compromise and post-exploitation behavior are investigated in operational SOC environments.

