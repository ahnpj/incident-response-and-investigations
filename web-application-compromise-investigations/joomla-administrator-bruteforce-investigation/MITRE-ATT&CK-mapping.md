# MITRE ATT&CK Mapping - Joomla Administrator Brute-Force Investigation

This document maps attacker behaviors observed during this investigation to MITRE ATT&CK tactics and techniques using direct evidence collected from HTTP request telemetry, authentication form submissions, and web application activity observed within Splunk.

All mappings are based on confirmed activity identified during analysis and are limited to behaviors directly supported by available evidence.

The purpose of this mapping is to support standardized incident classification, improve detection coverage validation, and align investigative findings with commonly used threat intelligence and incident response frameworks.

---

## How This Mapping Was Performed

Techniques were mapped by reviewing:

* HTTP POST requests targeting the Joomla administrator portal
* Source IP attribution
* Authentication request frequency
* Submitted username and password parameters
* User-Agent values associated with the activity
* Temporal patterns across authentication attempts

Each ATT&CK technique included below references the investigative findings that supported classification.

---

# MITRE ATT&CK Mapping (Narrative View)

## (1) Credential Access

### ▶ (1.1) Brute Force (T1110)

**Observed Behavior:**

A large volume of HTTP POST requests were directed at the Joomla administrator login portal hosted on `imreallynotbatman.com`.

Analysis identified 425 authentication attempts targeting the administrative login interface, with 412 requests originating from a single external IP address. The requests repeatedly submitted authentication credentials against the same administrative endpoint over a relatively short period of time.

The concentration of activity, repetition of login attempts, and focus on an authentication portal are all consistent with credential guessing behavior.

**Why This Maps to ATT&CK:**

ATT&CK defines Brute Force as attempts to gain access through repeated authentication attempts using multiple credential combinations.

The observed activity aligns directly with this definition because the attacker repeatedly submitted credentials against the Joomla administrator login interface in an attempt to obtain unauthorized access.

**Evidence Sources and Attribution:**

| Field                   | Value                             | Investigative Use                             |
| ----------------------- | --------------------------------- | --------------------------------------------- |
| HTTP Method             | POST                              | Indicates credential submission attempts      |
| Authentication Endpoint | `/joomla/administrator/index.php` | Confirms login portal targeting               |
| Event Volume            | 425 requests                      | Demonstrates repeated authentication attempts |
| Source IP               | 23.22.63.114                      | Links activity to a single external source    |

---

### ▶ (1.2) Password Guessing (T1110.001)

**Observed Behavior:**

Inspection of individual HTTP requests revealed authentication parameters submitted through the Joomla login form.

Review of the `form_data` field showed repeated attempts to authenticate using the username:

```text
admin
```

while password values changed across requests.

Additional analysis demonstrated that authentication attempts were generated using a Python-based client:

```text
Python-urllib/2.7
```

The repeated use of the same username combined with varying password values is consistent with password guessing activity targeting a known account.

**Why This Maps to ATT&CK:**

ATT&CK defines Password Guessing as a form of brute force in which attackers repeatedly test different passwords against one or more accounts.

The observed activity demonstrated systematic testing of multiple password values against the Joomla administrator account and therefore aligns directly with T1110.001.

**Evidence Sources and Attribution:**

| Field                   | Value                         | Investigative Use                   |
| ----------------------- | ----------------------------- | ----------------------------------- |
| Username                | `admin`                       | Identifies targeted account         |
| Form Data               | Multiple password submissions | Demonstrates password variation     |
| User-Agent              | `Python-urllib/2.7`           | Indicates automated tooling         |
| Authentication Requests | Repeated POST submissions     | Supports password guessing activity |

---

# MITRE ATT&CK Mapping (Table View)

| Tactic            | Technique ID | Technique Name    | Evidence Summary                                                           | Evidence Source                 |
| ----------------- | ------------ | ----------------- | -------------------------------------------------------------------------- | ------------------------------- |
| Credential Access | T1110        | Brute Force       | High volume of authentication attempts against Joomla administrator portal | HTTP request telemetry          |
| Credential Access | T1110.001    | Password Guessing | Repeated testing of password values against the administrator account      | Authentication form submissions |

This table provides a condensed ATT&CK reference suitable for reporting, investigation classification, and detection validation.

---

# Detection and Control Relevance

Mapping observed activity to MITRE ATT&CK supports defensive operations by:

* Highlighting detection opportunities for brute-force authentication activity
* Identifying password guessing attempts against administrative accounts
* Supporting alerting on excessive POST requests targeting authentication portals
* Improving visibility into automated credential attack behavior
* Supporting ATT&CK-aligned incident classification

Detection opportunities and defensive recommendations associated with these techniques are documented in:

* `case-report.md`
* `investigation-walkthrough.md`

---

# Notes and Assumptions

* Techniques were mapped solely from behaviors directly observed within the available dataset.
* No evidence of successful authentication was identified during the scope of this investigation.
* No evidence of account compromise, credential reuse, malware execution, persistence, or lateral movement was observed.
* Mapping avoids assumptions regarding attacker intent, tooling, or campaign attribution and focuses exclusively on observable activity.

This mapping reflects how MITRE ATT&CK can be applied to web application authentication abuse investigations using HTTP telemetry and authentication request analysis.
