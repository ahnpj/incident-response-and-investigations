# MITRE ATT&CK Mapping — Newly Provisioned Privileged Account Investigation

This document maps account management, privilege assignment, and authentication behaviors observed during this investigation to MITRE ATT&CK tactics and techniques using direct evidence from Windows Security Event Logs.

All mappings are based on confirmed activity identified during Event Viewer analysis rather than inferred attacker objectives, assumed tooling, or unobserved activity.

The purpose of this mapping is to support:

* Standardized incident classification
* Detection engineering and coverage validation
* Threat hunting development
* Identity and Access Management monitoring
* Alignment with MITRE ATT&CK methodology commonly used by SOC and incident response teams

---

### How This Mapping Was Performed

Techniques were mapped by reviewing:

* Authentication activity identified in Windows Security Event Logs
* User account creation events
* Security group membership modifications
* Privileged authentication events
* Reconstructed account lifecycle activity

Each technique below references the specific behaviors and investigative pivots that supported classification.

Only activity directly supported by Windows Security Event Log evidence has been mapped.

---

### MITRE ATT&CK Mapping (Narrative View)

### (1) Persistence

#### ▶ (1.1) Create Account: Local Account (T1136.001)

**Observed Behavior:**

A new user account named `SteveE` was created during the investigation timeline.

Review of Windows Security Event Logs identified:

```text
Event ID 4720
A user account was created
```

The event showed:

```text
Subject:
Jeff

New Account:
SteveE
```

This established that a new account was provisioned during the period under investigation.

**Why This Maps to ATT&CK:**

MITRE ATT&CK classifies creation of local accounts as a persistence technique because newly created accounts can provide ongoing access to systems and services.

The investigation does not establish malicious intent; however, the observed behavior aligns with ATT&CK's Create Account technique because a new account was successfully provisioned.

**Evidence Sources and Attribution:**

| Field           | Value                 | Investigative Use                  |
| --------------- | --------------------- | ---------------------------------- |
| Event ID        | 4720                  | Confirms account creation          |
| Subject Account | Jeff                  | Identifies actor performing action |
| New Account     | SteveE                | Identifies created account         |
| Event Timestamp | Security Log Timeline | Establishes activity sequence      |

---

### (2) Privilege Escalation

#### ▶ (2.1) Account Manipulation (T1098)

**Observed Behavior:**

The newly created account was assigned membership to multiple security groups.

Windows Security Event Logs recorded:

```text
Event ID 4732
A member was added to a security-enabled local group
```

Review confirmed membership assignment to:

```text
Users
ServiceAccount
Administrators
```

The most significant assignment was membership in:

```text
Administrators
```

which granted elevated privileges to the newly created account.

**Why This Maps to ATT&CK:**

ATT&CK classifies modification of account permissions and group memberships as Account Manipulation because these actions can alter access rights and increase privileges available to an identity.

The investigation confirms privilege assignment activity through security group membership changes.

**Evidence Sources and Attribution:**

| Field                | Value                                 | Investigative Use                         |
| -------------------- | ------------------------------------- | ----------------------------------------- |
| Event ID             | 4732                                  | Confirms group membership modification    |
| Modified Account     | SteveE                                | Identifies account receiving privileges   |
| Security Groups      | Users, ServiceAccount, Administrators | Establishes assigned permissions          |
| Timeline Correlation | Following account creation            | Establishes privilege assignment sequence |

---

### (3) Defense Evasion / Persistence Context

#### ▶ (3.1) Valid Accounts (T1078)

**Observed Behavior:**

Authentication activity involving valid Windows accounts was observed throughout the investigation.

Review of:

```text
4624
4672
```

events confirmed successful and privileged authentication activity associated with the account lifecycle under investigation.

The newly created account later authenticated successfully and generated Special Logon activity.

**Why This Maps to ATT&CK:**

ATT&CK's Valid Accounts technique covers use of legitimate accounts and credentials to access systems and perform actions.

The investigation does not establish credential theft or compromise. However, observed activity relied entirely on legitimate Windows account mechanisms rather than malware or exploitation.

**Evidence Sources and Attribution:**

| Field                   | Value                          | Investigative Use                  |
| ----------------------- | ------------------------------ | ---------------------------------- |
| Event ID                | 4624                           | Confirms successful authentication |
| Event ID                | 4672                           | Confirms privileged authentication |
| Account                 | SteveE                         | Identifies authenticated account   |
| Authentication Timeline | Following privilege assignment | Establishes account usage          |

---

### (4) Persistence and Privilege Escalation Combined Context

#### ▶ (4.1) Create Account + Account Manipulation Behavioral Chain

**Observed Behavior:**

The investigation reconstructed the following sequence:

```text
Account Creation
        ↓
Security Group Assignment
        ↓
Administrators Membership
        ↓
Authentication
        ↓
Privileged Authentication
```

This sequence represents a complete account provisioning and usage workflow.

**Why This Maps to ATT&CK:**

Although ATT&CK maps individual techniques separately, the observed activity demonstrates a behavioral chain commonly reviewed during identity-focused investigations.

The sequence combines:

* Create Account (T1136.001)
* Account Manipulation (T1098)
* Valid Accounts (T1078)

into a single account lifecycle.

This behavioral chain represented the highest-confidence investigative finding identified during analysis.

**Evidence Sources and Attribution:**

| Field                   | Value                               | Investigative Use                    |
| ----------------------- | ----------------------------------- | ------------------------------------ |
| Event IDs               | 4720, 4732, 4624, 4672              | Establish complete activity sequence |
| Timeline Reconstruction | Chronological Security Event review | Validates lifecycle                  |
| Account                 | SteveE                              | Primary account involved             |
| Privilege Assignment    | Administrators membership           | Confirms elevated access             |

---

### MITRE ATT&CK Mapping (Table View)

This table provides a condensed reference suitable for reporting, detection validation, ATT&CK coverage reviews, and threat hunting development.

| Tactic               | Technique ID | Technique Name                | Evidence Summary                                               | Evidence Source      |
| -------------------- | ------------ | ----------------------------- | -------------------------------------------------------------- | -------------------- |
| Persistence          | T1136.001    | Create Account: Local Account | New account `SteveE` created during investigation              | Event ID 4720        |
| Privilege Escalation | T1098        | Account Manipulation          | SteveE added to multiple groups including Administrators       | Event ID 4732        |
| Defense Evasion      | T1078        | Valid Accounts                | Legitimate Windows accounts used for authentication activity   | Event IDs 4624, 4672 |
| Persistence          | T1078        | Valid Accounts                | Newly provisioned account subsequently used for authentication | Event IDs 4624, 4672 |

---

### Detection and Control Relevance

Mapping these behaviors to ATT&CK highlights several important defensive opportunities.

Key monitoring priorities include:

* New account creation activity
* Administrative group membership changes
* Newly privileged account authentication
* After-hours administrative activity
* Account lifecycle correlation

The most valuable detection opportunities identified during investigation involve correlation of:

```text
4720
  ↓
4732
  ↓
4624
  ↓
4672
```

rather than monitoring individual Event IDs independently.

Detailed detection logic and monitoring recommendations are documented in:

* `detection-artifact-report.md`
* `detection-and-hardening-recommendations.md`

---

### Notes and Assumptions

* ATT&CK mappings are based solely on activity directly observed within Windows Security Event Logs.
* No malware execution evidence was available.
* No endpoint forensic evidence was available.
* No credential theft evidence was available.
* No phishing, exploitation, discovery, lateral movement, or command execution activity was observed.
* Techniques were selected conservatively to avoid over-classification beyond what the evidence supports.

This mapping reflects how ATT&CK is commonly applied during identity and access investigations involving account creation, privilege assignment, and authentication activity reconstructed from Windows Security Event Logs.
