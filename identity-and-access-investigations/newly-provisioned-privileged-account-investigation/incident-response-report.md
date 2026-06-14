# Incident Response Report — Newly Provisioned Privileged Account Investigation

### 1) Incident Classification

This section documents how the activity was categorized and prioritized based on observed account creation, privilege assignment, and authentication activity identified within Windows Security Event Logs.

* **Incident Type:** Suspicious Account Provisioning and Privileged Account Activity
* **Severity:** Medium
* **Status:** Investigation Complete — Authorization Not Confirmed
* **Primary Impact Area:** Identity and Access Management

Classification is based on evidence reconstructed in `case-report.md` and validated in `investigation-walkthrough.md`, including:

* Administrative account activity occurring outside expected working hours
* Creation of a new user account (`SteveE`) by an administrator account (`Jeff`)
* Assignment of the newly created account to multiple security groups
* Membership assignment to the local `Administrators` group
* Subsequent privileged authentication activity involving the newly created account

Unlike malware-driven incidents, the observed activity involved legitimate Windows account management functionality. The primary concern was whether the activity represented authorized administrative work or unauthorized account provisioning.

---

### 2) Detection Trigger

This section explains what initially indicated suspicious activity and why the case was escalated for investigation.

The investigation began after security monitoring identified administrator account logons occurring outside expected business hours.

The organization reported that:

* Jeff normally works between 9 AM and 4 PM
* Administrative account activity was observed outside expected working hours
* Additional activity may have occurred when Jeff was not expected to be present

These observations prompted review of the Windows Security Event Log export provided for analysis.

During investigation, analysts identified:

* Privileged logon activity
* User account creation activity
* Security group membership changes
* Subsequent authentication activity involving the newly created account

At this point, the activity required further validation because the investigation had expanded beyond simple after-hours authentication and now involved privileged account provisioning.

For reconstructed activity chronology, see `case-report.md` → **Investigation Timeline**.

For analyst workflow and evidence validation, see `investigation-walkthrough.md`.

---

### 3) Initial Triage Actions

This section outlines how analysts validated the activity, determined investigative scope, and assessed potential risk.

Triage focused on answering three core questions:

#### ▶ 3.1) Was administrative activity occurring outside expected working hours?

Analysts reviewed Windows Security Event Logs and reconstructed activity chronologically.

Review focused on:

* Authentication events
* Privileged logon events
* Administrative account activity

This step established the context for the investigation and validated that privileged activity existed within the reviewed time period.

#### ▶ 3.2) Were account management actions performed?

After identifying privileged activity, analysts reviewed account management events.

Analysis focused on:

* User account creation events
* Security group membership modifications
* Privilege assignment activity

This review identified creation of a new account named `SteveE`.

#### ▶ 3.3) Was the newly created account granted elevated access?

Analysts reviewed Security Group Management events to determine what permissions had been assigned.

Review confirmed:

* Membership in `Users`
* Membership in `ServiceAccount`
* Membership in `Administrators`

This significantly increased investigative priority because the newly created account had administrative privileges.

These triage steps established that the investigation involved both authentication activity and privileged account provisioning.

---

### 4) Containment Actions

This section documents actions that would typically be performed to immediately reduce risk while authorization of the activity is being validated.

Because this investigation was performed against a static event log export, containment actions were not executed directly.

In a production environment, containment would prioritize validation and privilege review.

#### ▶ 4.1) Account Validation

* **Validate ownership and business purpose of the SteveE account.**
  *Why:* The investigation confirmed account creation but could not determine whether the activity was approved.

* **Review change-management records.**
  *Why:* Administrative account creation may be legitimate if supported by approved business processes.

* **Confirm activity directly with Jeff and relevant administrators.**
  *Why:* Validation helps determine whether the observed activity reflects normal administration or unauthorized actions.

#### ▶ 4.2) Privileged Access Containment

* **Temporarily disable SteveE if authorization cannot be confirmed.**
  *Why:* Prevents continued use of elevated privileges while investigation continues.

* **Review membership of the Administrators group.**
  *Why:* Identifies unauthorized privilege assignments and validates access requirements.

* **Review recent privileged authentication activity.**
  *Why:* Determines whether additional administrative actions occurred after account creation.

These actions reduce risk while preserving evidence and supporting continued investigation.

---

### 5) Eradication Actions

This section documents actions that would be required if the activity is determined to be unauthorized.

Unlike malware-focused incidents, eradication would focus on identity cleanup and access-control correction.

#### ▶ 5.1) Remove Unauthorized Accounts

* Remove SteveE if the account lacks a legitimate business purpose.

*Why:* Eliminates unauthorized access pathways and removes persistence mechanisms established through account creation.

#### ▶ 5.2) Remove Unauthorized Privileges

* Remove inappropriate group memberships.
* Review all privileged groups for additional unauthorized changes.

*Why:* Account deletion alone may not address broader access-control modifications.

#### ▶ 5.3) Review Identity Activity

* Review recent administrative actions performed by Jeff and SteveE.
* Review authentication activity across relevant systems.

*Why:* Helps determine whether additional account management activity occurred beyond what was captured in the provided evidence.

These actions ensure that unauthorized identity changes are fully removed.

---

### 6) Recovery Actions

This section describes restoration of normal administrative operations after validation and remediation.

Recovery would focus on restoring trust in identity and access controls.

#### ▶ 6.1) Administrative Access Review

* Validate all privileged accounts currently authorized within the environment.
* Confirm appropriate ownership and business justification.

*Why:* Ensures privileged access remains aligned with operational requirements.

#### ▶ 6.2) Access Governance Restoration

* Re-establish approved access baselines.
* Document any approved administrative account creation activity.

*Why:* Helps prevent future uncertainty regarding account legitimacy.

#### ▶ 6.3) Security Monitoring Verification

* Confirm monitoring continues to generate alerts for account creation and privilege assignment activity.

*Why:* Ensures visibility remains intact following remediation.

---

### 7) Validation and Post-Incident Monitoring

This section explains how remediation effectiveness would be verified and what monitoring should remain in place.

Validation should confirm:

* No unauthorized privileged accounts remain active
* Administrative group membership reflects approved access
* No additional suspicious account creation activity occurs
* Authentication activity aligns with expected user behavior

Monitoring recommendations include:

* Alerting on Event ID `4720` (User Account Creation)
* Alerting on Event ID `4732` (Security Group Membership Changes)
* Monitoring Event ID `4672` (Special Logon)
* Alerting on administrator activity occurring outside expected working hours
* Monitoring newly created accounts added to privileged groups

These controls improve visibility into identity and access-related threats.

---

### 8) Communication and Coordination

This section summarizes coordination that would typically occur between security and operational teams.

Response would require collaboration between:

* **Security Operations:** Investigation, validation, and monitoring
* **System Administrators:** Account ownership validation and access review
* **Identity and Access Management Teams:** Privilege governance and access control review
* **Management:** Approval verification and risk assessment

Identity-related investigations frequently require business validation because technical evidence alone may not establish authorization.

---

### 9) Lessons Learned

This section captures defensive and response insights derived from the investigation.

Key lessons include:

* Administrative activity should be reviewed in business context, not solely through technical indicators.
* New account creation followed by administrative group assignment should receive elevated scrutiny.
* Authentication activity, account creation, and privilege assignment should be correlated rather than reviewed independently.
* Windows Security Event Logs provide valuable visibility into identity lifecycle activity.
* Monitoring for privileged account provisioning can identify suspicious activity before broader impact occurs.

These lessons informed the control improvements documented in `detection-and-hardening-recommendations.md`.

---

### 10) Related Documentation

* `investigation-walkthrough.md` — analyst workflow and event correlation process
* `case-report.md` — reconstructed account lifecycle and investigative findings
* `mitre-attack-mapping.md` — ATT&CK technique mapping and behavioral classification
* `incident-summary.md` — executive overview of investigation findings
* `detection-artifact-report.md` — Windows Security Event Log evidence and artifacts
* `detection-and-hardening-recommendations.md` — monitoring, governance, and hardening recommendations
