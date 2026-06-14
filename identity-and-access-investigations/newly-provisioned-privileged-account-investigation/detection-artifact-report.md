# Detection Artifact Report — Newly Provisioned Privileged Account Investigation

### 1) Purpose and Scope

This report documents **detection-relevant Windows Security Event Log artifacts** observed during investigation of suspicious administrative account activity involving account creation, security group membership changes, privilege assignment, and subsequent authentication activity.

The objective of this report is to provide **evidence-backed, investigation-anchored artifacts** that can be used for:

* Windows Security Event Log monitoring
* SIEM detection engineering and correlation rules
* Identity and Access Management (IAM) monitoring
* Privileged account monitoring
* Threat hunting across authentication and account management telemetry

All artifacts in this report are derived from investigation pivots and validation steps documented in:

* `investigation-walkthrough.md` — analyst workflow, Event Viewer analysis, and evidence validation
* `case-report.md` — reconstructed account lifecycle and investigative findings
* `mitre-attack-mapping.md` — ATT&CK technique classification and behavioral context

This report complements:

* `incident-response-report.md` — validation, containment, and remediation procedures
* `detection-and-hardening-recommendations.md` — long-term monitoring and prevention recommendations

---

### 2) Environment and Log Sources

This section summarizes telemetry sources used to identify and validate account management and authentication activity.

#### ▶ 2.1) Primary data sources used during investigation

* **Windows Security Event Logs**

  * Authentication activity
  * Logon events
  * Privileged logon events
  * Account creation activity
  * Security group membership changes

* **Windows Event Viewer**

  * Event review and filtering
  * Event timeline reconstruction
  * Event property analysis

* **Exported Event Log Evidence**

  * `Security Investigation.evtx`

#### ▶ 2.2) Affected identities

* **Administrator account under review:** Jeff
* **Newly created account:** SteveE
* **Investigation focus:** Identity and access activity rather than malware, endpoint execution, or network intrusion

---

### 3) High-Confidence Activity Sequence Anchors

This section documents timeline anchors used to reconstruct account provisioning and privileged account usage.

| Anchor Event              | Description                         | Evidence Source       | Investigation Pivot                 |
| ------------------------- | ----------------------------------- | --------------------- | ----------------------------------- |
| Privileged logon activity | Special Logon event identified      | Event ID 4672         | Established administrative activity |
| Account creation          | New user account created            | Event ID 4720         | Triggered account management review |
| Group assignment          | User added to Users group           | Event ID 4732         | Validated account provisioning      |
| Group assignment          | User added to ServiceAccount group  | Event ID 4732         | Expanded access review              |
| Privilege assignment      | User added to Administrators        | Event ID 4732         | Elevated investigative priority     |
| Account usage             | Newly created account authenticated | Event IDs 4624 / 4672 | Confirmed account utilization       |

These anchors were used to correlate authentication activity, account creation events, and privilege assignment into a complete account lifecycle.

---

### 4) Authentication and Privileged Logon Artifacts

This section documents authentication-related behaviors identified during the investigation.

#### ▶ 4.1) Artifact: Special Logon Event (Event ID 4672)

**Observed Behavior:**

* Windows generated Event ID `4672`
* Special privileges were assigned to a newly created logon session
* The event indicated privileged authentication activity

**Where Identified in Investigation:**

During initial timeline review, analysts sorted events chronologically and identified Event ID `4672` near the beginning of the available dataset. Because the investigation originated from reports of unusual administrator activity, privileged logon events became a primary investigative pivot.

Analysts subsequently filtered Event Viewer using:

```text
4672
```

to isolate privileged authentication events for review.

**Behavioral Significance:**

* Indicates an account received elevated privileges during logon
* Commonly associated with administrator accounts
* Frequently appears during privileged administrative activity
* Useful for identifying elevated authentication sessions

**Detection Guidance:**

Alert when:

* Event ID `4672` occurs outside expected working hours
* Newly created accounts generate Event ID `4672`
* Event ID `4672` follows account creation activity within a short time window

Increase severity when:

* The account recently received administrative privileges
* The event follows unusual account management activity

---

#### ▶ 4.2) Artifact: Successful Authentication Event (Event ID 4624)

**Observed Behavior:**

* Successful Windows authentication recorded
* Account session successfully established

**Where Identified in Investigation:**

After account creation and privilege assignment were identified, analysts reviewed successful authentication events to determine whether the newly created account had been used.

Event Viewer was filtered using:

```text
4624,4672
```

to review successful and privileged authentication activity together.

**Behavioral Significance:**

* Confirms account usage
* Indicates that credentials were successfully accepted
* Provides evidence that a provisioned account was actively utilized

**Detection Guidance:**

Alert when:

* Newly created accounts authenticate shortly after creation
* Administrative accounts authenticate outside approved schedules

Correlate with:

* Event ID `4720`
* Event ID `4732`
* Event ID `4672`

---

### 5) Account Management Artifacts

This section documents account lifecycle events identified during investigation.

#### ▶ 5.1) Artifact: User Account Creation (Event ID 4720)

**Observed Behavior:**

* A new user account named `SteveE` was created
* Account creation activity was performed by `Jeff`

**Where Identified in Investigation:**

After reviewing privileged authentication activity, analysts identified Event ID `4720` during chronological review of the Security Event Log.

Event properties revealed:

```text
Subject:
Jeff

New Account:
SteveE
```

This represented a major investigative pivot because the case evolved from an authentication review into an account provisioning investigation.

**Behavioral Significance:**

* Establishes account creation activity
* Identifies the actor responsible for account provisioning
* Creates a timeline anchor for subsequent privilege assignment review

**Detection Guidance:**

Alert when:

* Event ID `4720` occurs outside business hours
* Administrative users create accounts unexpectedly
* New accounts are created without associated change-management activity

Increase severity when:

* Account creation is followed by privileged group assignment
* Newly created accounts authenticate shortly after creation

---

### 6) Privilege Assignment Artifacts

This section documents access-control and privilege-related artifacts identified during investigation.

#### ▶ 6.1) Artifact: Users Group Membership Assignment

**Observed Behavior:**

* SteveE was added to the `Users` group

**Where Identified in Investigation:**

Review of Event ID `4732` showed SteveE being added to the default Users group shortly after account creation.

**Behavioral Significance:**

* Represents expected account provisioning behavior
* Establishes baseline account access

**Detection Guidance:**

Generally low priority when observed in isolation.

Correlate with:

* Account creation activity
* Additional privilege assignment events

---

#### ▶ 6.2) Artifact: ServiceAccount Group Membership Assignment

**Observed Behavior:**

* SteveE was added to the `ServiceAccount` group

**Where Identified in Investigation:**

A subsequent Event ID `4732` identified membership assignment to the ServiceAccount group.

**Behavioral Significance:**

* Indicates additional access beyond standard user permissions
* May indicate operational or administrative account usage

**Detection Guidance:**

Alert when:

* Newly created accounts are added to service-related groups
* Service-related groups receive unexpected members

Review:

* Account ownership
* Business justification
* Change records

---

#### ▶ 6.3) Artifact: Administrators Group Membership Assignment

**Observed Behavior:**

* SteveE was added to the local `Administrators` group

**Where Identified in Investigation:**

Review of Security Group Management events identified a third Event ID `4732` showing assignment to the Administrators group.

This represented the most significant privilege-related artifact identified during investigation.

**Behavioral Significance:**

* Grants elevated administrative privileges
* Significantly increases potential impact if activity is unauthorized
* Explains later Special Logon events generated by the account

**Detection Guidance:**

Alert when:

* Event ID `4732` adds a member to Administrators
* Newly created accounts receive administrative access

Increase severity when:

* Administrative access follows account creation within a short timeframe
* Administrative access occurs outside business hours

---

### 7) Account Lifecycle Artifacts

This section documents behaviors that become meaningful when multiple events are reviewed together.

#### ▶ 7.1) Artifact: Newly Created Account Lifecycle

**Observed Behavior:**

The following sequence was identified:

```text
Account Created
        ↓
Added to Users
        ↓
Added to ServiceAccount
        ↓
Added to Administrators
        ↓
Successful Authentication
        ↓
Privileged Authentication
```

**Where Identified in Investigation:**

Analysts reconstructed the sequence by correlating:

* Event ID `4720`
* Event ID `4732`
* Event ID `4624`
* Event ID `4672`

across the available timeline.

**Behavioral Significance:**

* Demonstrates complete account provisioning and usage workflow
* Higher-confidence indicator than any individual event alone
* Represents the strongest investigative finding in the case

**Detection Guidance:**

Alert when:

```text
4720
  ↓
4732
  ↓
4624 / 4672
```

occurs within a short time window.

This correlation provides substantially higher fidelity than monitoring each event independently.

---

### 8) Negative Findings and Investigation Limits

This section documents important observations that were not identified during investigation.

#### ▶ 8.1) No Evidence of Malware Activity

**Observed Behavior:**

* No malware execution evidence available
* No process telemetry available
* No endpoint forensic artifacts available

**Where Verified in Investigation:**

The provided evidence consisted solely of Windows Security Event Logs.

**Detection Implications:**

* Activity is identity-focused rather than malware-focused
* Additional endpoint telemetry would be required for malware validation

---

#### ▶ 8.2) No Evidence of Confirmed Account Compromise

**Observed Behavior:**

* No direct evidence proving Jeff's account was compromised

**Where Verified in Investigation:**

The Windows Security Event Log confirmed activity but did not establish intent or authorization.

**Detection Implications:**

* Activity should be classified as suspicious rather than confirmed malicious
* Additional validation is required before attributing activity to compromise

---

### 9) Cross-Source Correlation Opportunities

This section outlines detection strategies that mirror investigative pivots.

#### ▶ 9.1) Correlation 1: Account Creation → Administrative Group Assignment

**Signals:**

* Event ID `4720`
* Event ID `4732` (Administrators)

**Use Case:**

High-confidence indicator of newly provisioned privileged accounts.

---

#### ▶ 9.2) Correlation 2: Administrative Group Assignment → Privileged Authentication

**Signals:**

* Event ID `4732`
* Event ID `4672`

**Use Case:**

Detects newly privileged accounts actively being used.

---

#### ▶ 9.3) Correlation 3: Account Lifecycle Monitoring

**Signals:**

```text
4720
4732
4624
4672
```

**Use Case:**

Detects complete account provisioning and usage workflows.

---

### 10) Indicator Reliability Considerations

This section distinguishes behavioral indicators from isolated event indicators.

**Lower reliability indicators:**

* Single Event ID observed in isolation
* Individual successful logons
* Individual group membership changes

**Higher reliability indicators:**

* Account creation followed by administrative group assignment
* Administrative group assignment followed by privileged authentication
* Complete account lifecycle reconstruction
* Administrative activity occurring outside expected working hours

Behavior-based correlation provides stronger detection coverage than monitoring individual events independently.

---

### 11) Closing Summary

This investigation demonstrates how Windows Security Event Logs can be used to reconstruct identity and access activity without relying on endpoint forensic artifacts, malware indicators, or network telemetry.

The most significant artifacts identified were:

* Account creation activity
* Administrative privilege assignment
* Privileged authentication activity
* Complete account lifecycle reconstruction

Reliable detection depends on correlating:

* account creation,
* privilege assignment,
* authentication activity,
* and business context

rather than reviewing individual Windows Event IDs in isolation.

Organizations that correlate Windows account management activity with authentication behavior can identify suspicious privileged account provisioning activity before broader impact occurs.
