# Identity and Access Investigations

This folder contains investigations where the **primary security concern involves user accounts, authentication activity, authorization decisions, privilege assignment, or abnormal identity-related behavior**. These cases simulate how SOC analysts investigate suspicious account activity, authentication anomalies, privilege changes, account provisioning events, and access-control related incidents using identity and access telemetry.

> 👉 **Each folder represents one complete investigation**
> Every subfolder here is a **fully self-contained incident scenario**. Each one documents a single case from initial alert or observed anomaly through validation, scoping, timeline reconstruction, and response considerations.

> 👉 **Follow the investigation walkthrough first**
> Begin with `investigation-walkthrough.md` inside an investigation folder to see how I identified, pivoted on, correlated, and validated evidence throughout the investigation lifecycle.

Investigations in this category typically focus on:

* **Authentication and account activity anomalies**, including unusual logon behavior, after-hours access, suspicious account usage patterns, and authentication events that deviate from expected baselines
* **Account management and provisioning activity**, such as new account creation, privilege assignment, security group modifications, service account activity, and identity lifecycle changes
* **Access control and authorization investigations**, where permissions, group membership, administrative rights, or account privileges require validation to determine whether activity was expected or potentially unauthorized

Although these incidents may intersect with endpoint, email, or network telemetry, they are organized here when the **core investigative surface is identity, authentication, authorization, or access management activity rather than malware execution, phishing, or infrastructure compromise**.

---

### What’s in This Folder

Each investigation is contained in its **own dedicated folder** and represents **one complete incident scenario documented end-to-end**, including walkthroughs, reports, artifacts, investigative findings, and defensive recommendations.

Current investigations include:

* **Newly Created Privileged Account Investigation**
  (`newly-created-privileged-account-investigation`)
  Examines anomalous administrative account activity identified through Windows Security Event Logs, validating account creation activity, security group membership changes, privilege assignment, and subsequent authentication behavior through event correlation and timeline reconstruction.

---

### Investigation Documentation Structure

Each investigation is fully self-contained in its own case folder and includes documentation aligned with how identity- and access-related incidents are handled in real SOC workflows.

| File / Folder                                    | Purpose                               | Contents and Focus                                                                                                                                                |
| ------------------------------------------------ | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`investigation-walkthrough.md`**               | Analyst workflow and validation steps | Step-by-step actions showing how authentication activity, account changes, privilege assignments, and related evidence were identified, validated, and correlated |
| **`case-report.md`**                             | Formal incident narrative             | Timeline reconstruction, account activity analysis, investigative findings, and evidence-backed conclusions                                                       |
| **`incident-summary.md`**                        | Executive-level overview              | Initial alert, key findings, affected accounts, and final investigative outcome                                                                                   |
| **`detection-artifact-report.md`**               | Evidence and detection analysis       | Authentication logs, account management events, privilege changes, and supporting artifacts used throughout the investigation                                     |
| **`detection-and-hardening-recommendations.md`** | Defensive improvements                | Monitoring recommendations, alerting opportunities, access-control improvements, and identity security enhancements                                               |
| **`incident-response-report.md`**                | Remediation considerations            | Account review actions, privilege validation, credential management considerations, and post-investigation monitoring recommendations                             |
| **`mitre-attack-mapping.md`**                    | ATT&CK framework mapping              | Evidence-backed mapping of authentication, account manipulation, privilege escalation, or identity-related behaviors to ATT&CK techniques                         |
| **`images/` or `screenshots/`**                  | Validation artifacts                  | Event logs, authentication records, account management evidence, and supporting visual artifacts                                                                  |

Together, these documents separate **identity activity validation**, **access-control analysis**, **privilege review**, and **response planning** into clearly reviewable components tied to the same investigative narrative.

---

### Ongoing Development

Future investigations may expand into suspicious service account activity, account lockout investigations, password spraying activity, abnormal authentication behavior, privilege escalation events, unauthorized group membership changes, Entra ID investigations, Active Directory account misuse, and other identity-focused security incidents. New cases will continue to reflect how authentication and access-related threats are investigated in operational SOC environments.
