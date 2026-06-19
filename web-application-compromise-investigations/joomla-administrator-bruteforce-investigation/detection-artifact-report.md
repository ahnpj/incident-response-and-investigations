# Detection Artifact Report — Joomla Administrator Brute-Force Investigation

### 1) Purpose and Scope

This report documents HTTP, authentication, and behavioral artifacts observed during investigation of a brute-force password guessing campaign targeting the Joomla administrative login portal hosted on `imreallynotbatman.com`.

The purpose of this report is to provide detection-engineering–ready artifacts directly tied to analyst investigation pivots, demonstrating how suspicious authentication activity was identified, validated, and classified using web application telemetry.

Artifacts are mapped to the investigative workflow used throughout the case and reflect realistic SOC analysis techniques for identifying authentication abuse targeting publicly accessible administrative interfaces.

All artifacts are derived from investigative steps documented in:

* `investigation-walkthrough.md`
* `case-report.md`
* `MITRE-ATTACK-mapping.md`

This report complements:

* `detection-and-hardening-recommendations.md`
* `incident-summary.md`

---

## 2) Environment and Log Sources

This section summarizes the telemetry sources used throughout the investigation.

### ▶ 2.1) Primary Telemetry Sources

* HTTP Request Logs (`stream:http`)

  * HTTP methods
  * URIs
  * Source IP addresses
  * Destination IP addresses
  * User-Agent strings
  * Form submission data

* Splunk Search and Correlation

  * Event frequency analysis
  * Source attribution
  * Authentication request review
  * Credential submission analysis

### ▶ 2.2) Affected System

* **Target Application:** Joomla Content Management System
* **Target Authentication Interface:** Joomla Administrator Portal
* **Attack Surface:** Public-facing web authentication endpoint

---

## 3) High-Confidence Investigation Anchors

This section documents key investigative milestones used to structure analysis.

| Anchor Event                       | Description                                                           | Evidence Source               | Investigation Pivot            |
| ---------------------------------- | --------------------------------------------------------------------- | ----------------------------- | ------------------------------ |
| Authentication activity identified | Large volume of HTTP POST requests targeting administrator login page | HTTP telemetry                | Initiated investigation        |
| Source concentration observed      | Single external source responsible for majority of requests           | Source IP analysis            | Established attribution        |
| Target system identified           | Internal web server receiving requests identified                     | Destination IP analysis       | Confirmed affected asset       |
| Credential submissions reviewed    | Authentication parameters extracted from requests                     | Form data analysis            | Validated attack intent        |
| Automated tooling observed         | Python-based User-Agent identified                                    | HTTP metadata                 | Confirmed automation           |
| Password guessing validated        | Repeated password submissions against same account                    | Authentication request review | Confirmed brute-force activity |

These anchors formed the basis for all subsequent investigative pivots.

---

## 4) Authentication Abuse Artifacts

This section documents artifacts supporting classification of the activity as a brute-force password guessing attack.

### ▶ 4.1) Artifact: Repeated POST Requests to Administrative Login Portal

**Observed Behavior:**

A large number of HTTP POST requests targeted the Joomla administrative login page.

Target URI:

```text id="buhjxm"
/joomla/administrator/index.php
```

**Where Identified in Investigation:**

The investigation began by filtering HTTP telemetry for POST requests targeting the Joomla administrator interface. This immediately revealed a large concentration of authentication activity focused on a sensitive administrative endpoint.

**Behavioral Significance:**

* Indicates authentication activity rather than normal browsing
* Focuses analyst attention on credential abuse scenarios
* Identifies a high-value target within the application

**Detection Guidance:**

Alert when:

* Excessive POST requests target administrative authentication portals
* Request volume significantly exceeds established baselines

---

### ▶ 4.2) Artifact: Source IP Concentration

**Observed Behavior:**

A single external IP address generated the overwhelming majority of observed authentication requests.

Source IP:

```text id="5f4pah"
23.22.63.114
```

Associated Activity:

```text id="qf9h06"
412 of 425 authentication requests
```

**Where Identified in Investigation:**

Analysts reviewed source IP distributions using Splunk field analysis to identify which hosts were responsible for the observed activity.

**Behavioral Significance:**

* Strong indicator of automated activity
* Supports attribution of requests to a single source
* Reduces likelihood of legitimate administrator behavior

**Detection Guidance:**

Alert when:

* One source generates excessive authentication attempts
* Authentication activity significantly exceeds normal user behavior

---

### ▶ 4.3) Artifact: Administrative Account Targeting

**Observed Behavior:**

Authentication requests repeatedly targeted the same administrative username.

Observed Username:

```text id="gc6vqh"
admin
```

**Where Identified in Investigation:**

Review of HTTP form submission data revealed the username contained within authentication requests.

**Behavioral Significance:**

* Demonstrates focused targeting
* Indicates attacker awareness of common administrative account naming conventions
* Increases likelihood of credential attack activity

**Detection Guidance:**

Alert when:

* Administrative accounts receive excessive authentication failures
* Privileged accounts become the focus of repeated login attempts

---

## 5) Credential Guessing Artifacts

This section documents artifacts supporting classification as password guessing activity.

### ▶ 5.1) Artifact: Repeated Password Variation

**Observed Behavior:**

Authentication requests consistently targeted the same username while password values changed between requests.

**Where Identified in Investigation:**

Analysts reviewed authentication form submissions chronologically using extracted form data fields.

**Behavioral Significance:**

* Indicates systematic password testing
* Differentiates brute-force behavior from normal login failures
* Aligns with MITRE ATT&CK T1110.001 (Password Guessing)

**Detection Guidance:**

Alert when:

* Multiple password variations are submitted against a single account
* Authentication failures occur repeatedly within short time windows

---

### ▶ 5.2) Artifact: High-Volume Authentication Attempts

**Observed Behavior:**

Authentication attempts occurred repeatedly over the course of the observed activity window.

**Where Identified in Investigation:**

Analysts reconstructed authentication activity using timestamp analysis and chronological event review.

**Behavioral Significance:**

* Indicates sustained attack activity
* Supports brute-force classification
* Suggests automated execution

**Detection Guidance:**

Alert when:

* Authentication volume exceeds normal account behavior
* Administrative accounts receive repeated failures over time

---

## 6) Automated Tooling Artifacts

This section documents evidence indicating the requests were generated programmatically.

### ▶ 6.1) Artifact: Python-Based User-Agent

**Observed Behavior:**

Requests contained the following User-Agent value:

```text id="1cspjq"
Python-urllib/2.7
```

**Where Identified in Investigation:**

User-Agent fields were reviewed within individual HTTP request records.

**Behavioral Significance:**

* Indicates scripted activity
* Suggests automation rather than browser-based interaction
* Supports brute-force classification

**Detection Guidance:**

Alert on authentication activity originating from:

* Python-urllib
* curl
* wget
* Known automation frameworks

---

## 7) Absence of Compromise Indicators

This section documents notable investigative findings that were not observed.

### ▶ 7.1) No Confirmed Successful Authentication

**Observed Behavior:**

No authentication success events were identified within the available investigation scope.

**Where Verified in Investigation:**

Analysts reviewed available authentication telemetry and HTTP request data for evidence of successful login activity.

**Detection Implications:**

* Activity classified as attempted credential compromise
* Successful account compromise could not be validated

---

### ▶ 7.2) No Observed Post-Authentication Activity

**Observed Behavior:**

No authenticated session creation, administrative actions, or protected resource access were identified.

**Detection Implications:**

* Investigation remained focused on authentication abuse
* No evidence of application compromise was observed

---

## 8) Cross-Source Correlation Opportunities

### ▶ 8.1) Correlation 1: Administrative Login Portal Abuse

**Signals:**

* POST requests
* Administrative login URI
* High request volume

**Use Case:**

Detect brute-force activity against administrative authentication portals.

---

### ▶ 8.2) Correlation 2: Administrative Account Targeting

**Signals:**

* Username targeting
* Repeated failures
* Password variation

**Use Case:**

Detect password guessing against privileged accounts.

---

### ▶ 8.3) Correlation 3: Automated Authentication Activity

**Signals:**

* Python-based User-Agent
* High request frequency
* Authentication endpoint targeting

**Use Case:**

Detect scripted authentication abuse.

---

## 9) Indicator Reliability Considerations

**Lower Reliability Indicators**

* Source IP addresses
* User-Agent values

**Higher Reliability Indicators**

* Repeated password guessing behavior
* High-volume authentication attempts
* Administrative account targeting
* Authentication endpoint abuse

Behavioral indicators remain effective even when attackers modify infrastructure or client characteristics.

---

## 10) Closing Summary

This investigation demonstrates how HTTP telemetry alone can provide sufficient evidence to identify and validate brute-force password guessing activity against publicly accessible administrative interfaces.

By correlating:

* Authentication request volume
* Source attribution
* Credential submissions
* Administrative account targeting
* Automated tooling indicators

analysts were able to confidently classify the activity as a credential access attempt aligned with MITRE ATT&CK Brute Force and Password Guessing techniques.

The detection opportunities documented throughout this report provide multiple paths for earlier identification of similar authentication abuse campaigns in production environments.
