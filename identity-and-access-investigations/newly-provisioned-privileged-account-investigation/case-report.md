# Case Report — Newly Provisioned Privileged Account Investigation

**Case Type:** Identity and Access Investigation
**Primary Abuse Pattern:** Newly created account assigned administrative privileges and subsequently used following anomalous administrative activity
**Status:** Closed (investigation complete)
**Confidence Level:** High — account creation, privilege assignment, and authentication activity confirmed through Windows Security Event Log evidence

---

### 1) Executive Summary

This case investigates suspicious administrative account activity identified through Windows Security Event Log monitoring. The investigation was initiated after an administrator account associated with employee **Jeff S** was observed logging in outside expected working hours, including periods when the employee was not expected to be in the office.

Analysis of the provided Windows Security Event Log export revealed that the account under review created a new user account named `SteveE`, assigned the account to multiple security groups including the local `Administrators` group, and that the newly created account subsequently generated privileged authentication activity.

The investigation focused on reconstructing account lifecycle activity using Windows Security Event Logs to determine:

* Whether privileged administrative activity occurred
* Whether new accounts were created
* What permissions were assigned
* Whether the new account was subsequently used
* Whether the observed behavior warranted escalation

Evidence supporting these conclusions includes:

* Privileged authentication events (`4672`)
* User account creation events (`4720`)
* Security group membership modifications (`4732`)
* Successful authentication activity (`4624`)

---

### 2) Incident Background

The organization recently implemented monitoring of Windows Security Event Logs to improve visibility into administrative activity and authentication behavior.

After several days of monitoring, administrators identified unusual activity involving an administrator account associated with employee Jeff S.

The organization provided the following context:

* Jeff works between 9 AM and 4 PM
* Administrative activity was observed outside expected working hours
* Additional activity may have occurred when Jeff was not expected to be present

Because administrator accounts possess elevated privileges, the activity required investigation to determine whether:

* Administrative actions had been performed
* New accounts had been provisioned
* Additional privileged access had been established

The investigation focused on reconstructing activity using Windows Security Event Logs rather than endpoint or network telemetry.

This mirrors a common SOC workflow where unusual authentication activity triggers review of identity and access management events.

---

### 3) Scope

This section defines which systems, identities, and evidence sources were included in the investigation, as well as what activity could not be validated using the available dataset.

#### ▶ 3.1) In Scope

| Category                          | Included Items                                            |
| --------------------------------- | --------------------------------------------------------- |
| **Accounts Reviewed**             | • Jeff<br>• SteveE                                        |
| **Primary Evidence Source**       | • `Security Investigation.evtx`                           |
| **Authentication Activity**       | • Successful logons (`4624`)<br>• Special Logons (`4672`) |
| **Account Management Activity**   | • User account creation (`4720`)                          |
| **Privilege Assignment Activity** | • Security group membership changes (`4732`)              |

#### ▶ 3.2) Out of Scope / Not Observed

* Endpoint telemetry
* PowerShell logs
* Process execution logs
* Sysmon telemetry
* Network activity
* Domain controller replication events
* Change-management records
* User interviews
* Ticketing systems

No evidence of malware execution, lateral movement, command execution, or endpoint compromise was available within the provided dataset.

---

### 4) Environment

This investigation analyzed Windows identity and access activity using native Windows Security Event Logs.

#### ▶ 4.1) Affected System Operating System

* Microsoft Windows

#### ▶ 4.2) Analyst Operating System

* Microsoft Windows

#### ▶ 4.3) Platforms and Services

* Windows Security Event Logging
* Windows Event Viewer
* Local account management
* Local security groups

#### ▶ 4.4) Data Sources Reviewed

* Windows Security Event Logs
* Authentication events
* Account management events
* Security group membership events
* Privileged authentication events

**Analyst Note:**
Findings are based exclusively on Windows Security Event Log evidence. No supporting endpoint, network, or cloud identity telemetry was available during the investigation.

---

## 5) Evidence Summary

This section summarizes the primary evidence used to reconstruct account creation, privilege assignment, and authentication activity observed during the investigation.

Detailed Event IDs, detection artifacts, and correlation opportunities are documented separately in:

`detection-artifact-report.md`

This separation reflects common SOC workflows where investigation narratives and detection engineering documentation are maintained independently.

---

#### ▶ 5.1 Authentication Evidence — Privileged Logon Activity

Initial review focused on privileged authentication activity because the investigation originated from reports of unusual administrator logons.

Event Viewer review identified:

```text
Event ID 4672
Special Logon
```

These events indicate that a logon session received elevated privileges.

Review of these events established the presence of privileged administrative activity within the available timeline.

(See `investigation-walkthrough.md` → *Privileged Authentication Review*)

---

#### ▶ 5.2 Account Creation Evidence

After authentication review, investigation pivoted to account management activity.

Analysis identified:

```text
Event ID 4720
User Account Created
```

Event details showed:

**Subject:**

```text
Jeff
```

**New Account:**

```text
SteveE
```

This established that Jeff created a new account named SteveE.

(See `investigation-walkthrough.md` → *Account Creation Analysis*)

---

#### ▶ 5.3 Security Group Membership Evidence

Following account creation, analysts reviewed security group membership changes.

Multiple:

```text
Event ID 4732
```

events were identified.

These showed that SteveE was added to:

* Users
* ServiceAccount
* Administrators

Membership in the Administrators group represented the most significant privilege-related finding identified during investigation.

(See `investigation-walkthrough.md` → *Security Group Membership Analysis*)

---

#### ▶ 5.4 Account Usage Evidence

After validating account creation and privilege assignment, analysts reviewed authentication activity associated with the newly created account.

Review of:

```text
4624
4672
```

events confirmed that SteveE later authenticated and generated privileged logon activity.

This established that the account was not only created and assigned privileges, but was subsequently used.

(See `investigation-walkthrough.md` → *Account Usage Validation*)

---

### 6) Investigation Timeline (Condensed)

The timeline below reflects the reconstructed sequence of observed account activity rather than analyst actions.

Detailed investigative workflow and Event Viewer analysis are documented separately in:

`investigation-walkthrough.md`

| Phase | Activity                                                                    |
| ----- | --------------------------------------------------------------------------- |
| T0    | Administrative activity identified during security monitoring               |
| T1    | Privileged authentication activity observed                                 |
| T2    | Jeff creates new account `SteveE`                                           |
| T3    | SteveE added to Users group                                                 |
| T4    | SteveE added to ServiceAccount group                                        |
| T5    | SteveE added to Administrators group                                        |
| T6    | SteveE successfully authenticates                                           |
| T7    | SteveE generates privileged logon activity                                  |
| T8    | Investigation concludes suspicious privileged account provisioning activity |

---

## 7) Indicators of Interest

The indicators listed below represent investigation-relevant artifacts associated with account provisioning, privilege assignment, and authentication activity observed during the case.

Field-level detection logic and Event ID analysis are documented separately in:

`detection-artifact-report.md`

---

#### ▶ 7.1 Authentication Indicators

**Relevant Event IDs:**

* `4624`
* `4672`

**Associated Activity:**

* Successful logons
* Privileged logon sessions
* Elevated account usage

**Detection Use Cases:**

* Administrative activity outside business hours
* Newly provisioned account usage
* Privileged authentication monitoring

---

#### ▶ 7.2 Account Management Indicators

**Relevant Event IDs:**

* `4720`

**Observed Account:**

```text
SteveE
```

**Associated Activity:**

* New account creation
* Administrative account management

**Detection Use Cases:**

* Account creation monitoring
* New account lifecycle tracking
* Administrative provisioning review

---

#### ▶ 7.3 Privilege Assignment Indicators

**Relevant Event IDs:**

* `4732`

**Observed Groups:**

```text
Administrators
ServiceAccount
Users
```

**Associated Activity:**

* Privilege assignment
* Access-control modification
* Administrative access provisioning

**Detection Use Cases:**

* Administrative group membership changes
* Newly privileged account monitoring
* Access governance review

---

#### ▶ 7.4 Behavioral Indicators

The highest-confidence behavioral pattern identified during investigation was:

```text
4720
    ↓
4732
    ↓
4624
    ↓
4672
```

This sequence represents:

* Account creation
* Privilege assignment
* Successful authentication
* Privileged account usage

**Detection Use Cases:**

* Account lifecycle monitoring
* Suspicious privileged account provisioning
* Identity-focused threat hunting

---

#### ▶ 7.5 Indicator Limitations

The available evidence confirms account creation, privilege assignment, and account usage.

However, the logs alone do not confirm:

* Malicious intent
* Account compromise
* Unauthorized activity
* Insider threat activity

Because authorization could not be validated, the activity should be considered suspicious rather than confirmed malicious.

Behavioral correlation remains more valuable than isolated Event IDs.

---

### 8) Case Determination

**Final Determination:**

Suspicious privileged account provisioning activity identified through Windows Security Event Log analysis.

The investigation confirmed that:

* Jeff created a new account named SteveE
* SteveE received multiple group assignments
* SteveE received administrative privileges
* SteveE subsequently authenticated and generated privileged logon activity

The evidence supports a complete account lifecycle reconstruction.

However, the available logs do not independently establish:

* Whether the activity was authorized
* Whether Jeff's account was compromised
* Whether SteveE was used maliciously

As a result, the activity is classified as suspicious identity and access activity requiring validation rather than confirmed compromise.

---

### 9) Recommended Follow-Ups (Case Closure Actions)

#### ▶ 9.1 Immediate Validation

* Confirm ownership and business purpose of SteveE
* Review change-management records
* Validate account creation activity with Jeff

#### ▶ 9.2 Access Review

* Review membership of privileged groups
* Confirm administrative access requirements
* Review additional SteveE activity

#### ▶ 9.3 Monitoring Improvements

* Alert on Event ID 4720
* Alert on Event ID 4732 involving Administrators
* Monitor privileged authentication activity
* Correlate account lifecycle events

---

### 10) Supporting Reports (In This Folder)

* `investigation-walkthrough.md` — analyst workflow, Event Viewer analysis, screenshots, and evidence validation
* `incident-summary.md` — executive-level overview and business impact
* `incident-response-report.md` — containment, remediation, and monitoring recommendations
* `detection-artifact-report.md` — Event IDs, artifacts, and detection pivots
* `detection-and-hardening-recommendations.md` — preventive controls and monitoring improvements
* `mitre-attack-mapping.md` — ATT&CK mapping and behavioral classification
* `images/` — screenshots referenced throughout investigation documentation
* `README.md` — investigation overview and repository navigation

---

### 11) MITRE ATT&CK Mapping

The mappings below provide a high-level summary of observed behaviors identified during investigation.

For expanded ATT&CK analysis and supporting evidence, see:

`mitre-attack-mapping.md`

#### ▶ 11.1 Technique Mapping

* Persistence — Create Account: Local Account (T1136.001)
* Privilege Escalation — Account Manipulation (T1098)
* Defense Evasion — Valid Accounts (T1078)
* Persistence / Privilege Escalation — Valid Accounts (T1078)

#### ▶ 11.2 MITRE ATT&CK Mapping (Table View)

| Tactic               | Technique                                     | Description                                                              |
| -------------------- | --------------------------------------------- | ------------------------------------------------------------------------ |
| Persistence          | **Create Account: Local Account (T1136.001)** | New account SteveE created by Jeff                                       |
| Privilege Escalation | **Account Manipulation (T1098)**              | SteveE added to privileged groups                                        |
| Defense Evasion      | **Valid Accounts (T1078)**                    | Legitimate account mechanisms used for authentication and administration |
| Persistence          | **Valid Accounts (T1078)**                    | Newly created account used for privileged authentication activity        |
