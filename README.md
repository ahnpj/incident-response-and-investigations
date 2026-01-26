## Incident Response and Investigations

This repository contains **hands-on security investigations** modeled after real SOC and blue-team workflows. Each case simulates how suspicious activity or alerts are triaged, validated, scoped, and resolved using multiple sources of telemetry.

The repository is organized into **category folders based on primary attack surface and investigation focus** (such as identity, endpoint, intrusion, and web applications). Each category contains multiple fully self-contained investigations, with each folder representing **one complete incident scenario documented end-to-end** — including analysis, evidence, and response considerations.

Rather than focusing on isolated tools or one-off techniques, these investigations emphasize:

- Evidence-based analysis
- Cross-log correlation
- Attacker behavior mapping (MITRE ATT&CK)
- Clear documentation of investigative reasoning and outcomes

Each investigation is written as a self-contained case file, showing how an analyst moves from initial signal to confirmed findings and response considerations.

---

### How This Repository Is Organized

This repository is organized into **category folders**, which are the top-level folders you see at the top when browsing the repository.  

Each category represents a major security domain and primary attack surface used to group related investigations. Investigations are placed into one of these categories based on **where the attack originates and how the incident is primarily investigated**, not by which tools or logs happen to appear in the case.

Each investigation is fully self-contained inside its own folder and includes all documentation, evidence, and analysis needed to understand that single incident from start to finish.

#### Category Folders (Top-Level Directories)

| Category Folder | Investigation Focus | What You Will Find Inside |
|---------------|----------------------|----------------------------|
| **Identity and Email Compromise** | Attacks where identity platforms or messaging systems are the primary attack surface. | Investigations involving credential abuse, mailbox manipulation, account takeover, business email compromise (BEC), and abuse of authentication workflows. Evidence may include identity logs, mailbox audit data, and message artifacts. |
| **Endpoint Compromise and Persistence** | Host-based attacks where endpoint telemetry and system artifacts are central to detection and validation. | Investigations involving malware execution, unauthorized processes, persistence mechanisms (registry, scheduled tasks, services), account creation, and abuse of built-in system utilities. Evidence typically includes Windows event logs, Sysmon, and file system artifacts. |
| **Intrusion and Lateral Movement** | Multi-stage intrusions that progress across systems and network paths. | Investigations that reconstruct attacker movement from initial access through credential abuse, privilege escalation, and lateral movement using firewall logs, authentication telemetry, endpoint artifacts, and network indicators. |
| **Web Application Compromise** | Attacks where web applications or CMS platforms are the initial access vector. | Investigations involving authentication abuse, vulnerability scanning, file upload exploitation, web shells, and defacement. Evidence includes HTTP traffic, IDS alerts, firewall logs, and host telemetry. |

---

### How Investigations Are Structured & Organized

Investigations are organized using a two-level hierarchy:

1. **Category folders** — group related incident types by primary attack surface and investigation focus  
2. **Investigation folders** — each individual incident scenario lives in its own folder inside a category

Each investigation folder is fully self-contained and represents **one complete case**.

**IMPORTANT:** Investigations are grouped by **primary attack surface and investigation focus**, not strictly by which tools or logs were involved.

In real SOC work, incidents commonly span multiple telemetry sources (for example: web logs, firewall telemetry, identity events, and endpoint artifacts in the same case). To reflect that reality, each investigation is categorized by the **security control area where the incident originates or is primarily investigated**, rather than every system touched during analysis.

This structure mirrors how security teams operationally triage incidents and assign investigative ownership.

---

### How These Investigations Are Designed

This repository is **investigation-first**, not procedural.

You will find:

- Case-style investigation reports
- Step-by-step analyst pivots and validation workflows
- Timelines, screenshots, and extracted artifacts
- Detection and hardening observations tied directly to findings
- MITRE ATT&CK mappings

Each investigation documents not just what happened, but how conclusions were reached, why specific pivots were performed, and what evidence supports each decision.

Operational documentation such as triage guides, response checklists, and standard operating procedures are intentionally maintained in a separate repository so that this repository remains focused on real investigative work, not generalized playbooks.

---

### Standard Files in Each Investigation Folder

While not every case requires every file, investigations typically include the following supporting documents:

| File / Folder | Purpose | Contents and Focus |
|------------|--------|--------------------|
| **Investigation Walkthrough** (`investigation-walkthrough.md`) | Step-by-step analyst workflow and validation process. | Documents analyst actions and pivots performed during the case, showing how evidence was identified, validated, and correlated across multiple data sources. |
| **Case Report** (`case-report.md`) | Formal incident narrative and findings. | Provides structured incident documentation including scope, methodology, confirmed findings, and response considerations. |
| **Incident Summary** (`incident-summary.md`) | Executive-level overview of the incident. | Summarizes what happened, how it was detected, and the final outcome of the investigation for non-technical stakeholders. |
| **Detection and Artifact Analysis** (`detection-artifact-report.md`) | Detailed breakdown of technical evidence and detections. | Documents logs, alerts, and forensic artifacts, including where each was identified during the investigation and what conclusions were drawn from each artifact. |
| **Detection and Hardening Recommendations** (`detection-and-hardening-recommendations.md`) | Defensive improvements derived from investigation findings. | Provides actionable recommendations based on gaps observed during the investigation, including logging gaps, detection opportunities, and control improvements. |
| **Incident Response Report** (`incident-response-report.md`) | Operational response and remediation guidance. | Covers containment, eradication, recovery, and post-incident considerations following confirmation of malicious activity. |
| **MITRE ATT&CK Mapping** (`mitre-attack-mapping.md`) | Mapping of observed behaviors to ATT&CK framework. | Provides evidence-backed mapping of observed behaviors to MITRE ATT&CK tactics and techniques tied to specific investigation steps. |
| **Screenshots and Supporting Evidence** (`images/` or `screenshots/`) | Visual and log-based validation artifacts. | Contains log excerpts, visual artifacts, and validation evidence referenced throughout the documentation to support analytical conclusions. |

Together, these files separate **analyst workflow**, **incident reconstruction**, and **evidence validation** into clear, reviewable components while remaining tied to the same investigation narrative.

---

### Category Folders and Current Investigations

Each category folder may contain **multiple investigation folders**, with each investigation representing a separate incident scenario.

#### Identity and Email Compromise Investigations  
`identity-and-email-compromise-investigations/`

Incidents where identity platforms or messaging services are the primary attack surface, including credential abuse, mailbox manipulation, and business email compromise (BEC). Investigations are grouped here when the **core security failure is unauthorized access to accounts or messaging workflows**.

Current investigations:

- **Business Email Compromise (BEC) — Mailbox Rule Abuse and Account Takeover**  
  Investigates how attackers abuse Exchange inbox rules to suppress financial communications after compromising executive credentials, including validation of unauthorized rule creation and associated identity activity.


#### Endpoint Compromise and Persistence Investigations  
`endpoint-compromise-and-persistence-investigations/`

Host-based compromise scenarios involving malware execution, persistence mechanisms, and abuse of built-in system utilities. Cases are categorized here when **endpoint telemetry and host artifacts are central to detection and validation**.

Current investigations:

- **Endpoint Cryptominer Infection — Suspicious Process Execution**  
  Detects abnormal process behavior consistent with cryptomining malware using Windows process creation telemetry and execution context.

- **Windows Host Compromise — Backdoor Account and Registry-Based Persistence**  
  Analyzes unauthorized account creation and registry autorun mechanisms used to maintain long-term access to a compromised workstation.

- **Windows Malware Triage — Living-off-the-Land Binary (LoLBin) Abuse and Payload Validation**  
  Validates suspicious binaries and persistence techniques using file reputation, digital signatures, scheduled tasks, and registry artifacts.


#### Intrusion and Lateral Movement Investigations  
`intrusion-and-lateral-movement-investigations/`

Multi-stage intrusion scenarios involving privilege escalation, remote service exploitation, and movement between systems. Investigations are placed here when the objective is to **reconstruct attacker progression across hosts and network paths**.

Current investigations:

- **Windows Service Exploitation — Print Spooler Remote Code Execution (RCE)**  
  Examines exploitation of the Print Spooler service leading to code execution and elevated privileges on a Windows server.

- **Intrusion Lifecycle Investigation — Lateral Movement Across Windows Hosts**  
  Tracks attacker behavior from initial access through credential-based lateral movement using firewall, authentication, and host telemetry.


#### Web Application Compromise Investigations  
`web-application-compromise-investigations/`

Attacks where web applications or CMS platforms are the initial access vector, including authentication abuse and file upload exploitation. Cases are grouped here when **application-layer behavior and HTTP activity are the primary investigation surfaces**.

Current investigations:

- **Web Application Account Compromise — Brute-Force Authentication Abuse**  
  Analyzes repeated authentication attempts against a web application leading to successful account takeover.

- **Web Server Defacement — Malicious File Upload Exploitation**  
  Investigates exploitation of file upload functionality resulting in unauthorized script deployment and website defacement.

---

### Overlap Between Categories

Overlap between technical domains is expected and intentional.

A single incident may involve:

- Identity and authentication logs
- Firewall and IDS telemetry
- Endpoint execution artifacts
- Application server logs

Rather than duplicating investigations across multiple categories, each case is grouped by the **primary surface that was exploited and investigated**, while the investigation documentation itself includes all supporting telemetry required to validate findings.

This reflects how real SOC investigations operate and avoids artificially separating evidence that must be analyzed together.

---

### Relationship to Workflows and Playbooks

This repository documents **what happened and how it was investigated**.

Operational workflows such as triage procedures, enrichment steps, and response checklists are maintained separately in:

`security-operations-workflows/`

Where relevant, investigations may reference related workflows to demonstrate how documented procedures translate into real investigative activity and analyst decision-making.

---

### Ongoing Development

Investigations may be expanded over time as additional analysis techniques, tooling, or contextual validation are added. Updates are intended to reflect iterative improvement, similar to how detection and response processes mature in production environments.





