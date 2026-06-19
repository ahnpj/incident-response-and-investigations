# Case Report — Joomla Administrator Brute-Force Investigation

**Case Type:** Web Application Security Incident / Authentication Abuse
**Primary Abuse Pattern:** Automated brute-force authentication attempts targeting a Joomla administrative login portal
**Status:** Closed (investigation complete)
**Confidence Level:** High — supported by HTTP request telemetry, authentication form submissions, source attribution, and request metadata

---

## 1) Executive Summary

This investigation was initiated after security monitoring identified suspicious authentication activity targeting the Joomla administrative interface hosted on `imreallynotbatman.com`.

Analysis of web application telemetry revealed a high volume of HTTP POST requests directed at the Joomla administrator login portal. The overwhelming majority of requests originated from a single external IP address and were associated with repeated submission of authentication credentials against the administrative login endpoint.

Further review of HTTP request metadata, submitted form parameters, and client characteristics confirmed the activity was consistent with an automated brute-force password guessing campaign. Evidence showed repeated targeting of the Joomla administrative account using scripted tooling designed to systematically test credential combinations.

While the investigation confirmed active credential guessing behavior against the administrative interface, no evidence reviewed during the scope of this investigation established successful authentication or post-authentication activity.

---

## 2) Incident Background

The Security Operations team received an alert indicating potential brute-force activity against a publicly accessible Joomla web application.

Initial information provided to the investigation identified the administrative login page as:

```text
http://imreallynotbatman.com/joomla/administrator/index.php
```

Because administrative accounts provide elevated access to application functionality and configuration settings, the activity was treated as a potentially significant security event requiring immediate review.

The investigation sought to determine:

* Whether authentication attempts were automated
* Which source system generated the activity
* Which asset was targeted
* Whether submitted credentials could be identified
* Whether access was successfully obtained
* Whether evidence of post-authentication activity existed

---

## 3) Scope

This section defines the systems, evidence sources, and activities included within the investigation.

### ▶ 3.1) In-Scope

| Category                            | Included Items                                                                             |
| ----------------------------------- | ------------------------------------------------------------------------------------------ |
| **Application Under Investigation** | Joomla web application                                                                     |
| **Primary Evidence Sources**        | Splunk BOTSv1 dataset                                                                      |
| **Log Sources Reviewed**            | stream:http                                                                                |
| **Behavioral Focus Areas**          | Authentication attempts, source attribution, credential submissions, HTTP request analysis |

### ▶ 3.2) Out-of-Scope / Not Observed

* Host-level compromise
* Malware execution
* Web shell deployment
* Lateral movement
* Privilege escalation
* Successful authentication events
* Post-authentication activity

Analysis was limited to available HTTP telemetry and authentication-related activity.

---

## 4) Environment

This investigation analyzed web application telemetry using Splunk.

### ▶ 4.1) Investigation Platform

* Splunk Enterprise

### ▶ 4.2) Dataset

* BOTSv1

### ▶ 4.3) Data Sources Reviewed

#### HTTP Traffic Telemetry (`stream:http`)

Fields reviewed included:

* Source IP address
* Destination IP address
* HTTP method
* URI
* User-Agent
* Form submission data
* Timestamps

### ▶ 4.4) Target Application

* Joomla Content Management System (CMS)
* Administrative authentication portal

---

## 5) Evidence Summary

This section summarizes the primary evidence used to validate brute-force authentication activity.

### ▶ 5.1) Initial Detection

Analysis of HTTP telemetry identified repeated POST requests directed at the Joomla administrator login endpoint.

Search executed:

```spl
index="botsv1" sourcetype="stream:http" http_method=POST uri="/joomla/administrator/index.php"
```

Results:

```text
425 matching events
```

The volume of authentication requests warranted additional investigation.

---

### ▶ 5.2) Source Attribution

Review of source IP distribution revealed a single external host responsible for the overwhelming majority of requests.

**Source IP:**

```text
23.22.63.114
```

**Associated Events:**

```text
412 of 425 events
```

**Percentage of Activity:**

```text
96.94%
```

The concentration of activity strongly suggests automated behavior rather than legitimate administrative access.

---

### ▶ 5.3) Target Asset Identification

Review of destination information identified the internal system receiving authentication requests.

**Destination IP:**

```text
192.168.250.70
```

The destination host was identified as the web server hosting the Joomla application.

---

### ▶ 5.4) Authentication Request Analysis

Inspection of individual HTTP POST requests revealed submitted authentication parameters within the `form_data` field.

Review of a representative request confirmed the attacker was attempting to authenticate using the administrative username:

```text
admin
```

Additional observations included:

* HTTP Method: POST
* Destination Port: 80
* Authentication Endpoint: `/joomla/administrator/index.php`
* User-Agent: `Python-urllib/2.7`

The User-Agent string indicates the requests originated from a Python-based script rather than a traditional web browser.

---

### ▶ 5.5) Credential Guessing Activity

Chronological review of submitted form data demonstrated repeated authentication attempts against the same administrative account.

Observed behavior included:

* Consistent username targeting
* Repeated password changes
* High-volume authentication attempts
* Automated request generation

This activity is consistent with a brute-force password guessing campaign.

---

### ▶ 5.6) Automated Tooling Indicators

Multiple indicators suggest the activity was automated rather than human-driven:

* High request volume
* Repetitive authentication behavior
* Consistent source attribution
* Python-based User-Agent
* Rapid submission of credential variations

These characteristics align with scripted credential attack activity.

---

## 6) Investigation Timeline (Condensed)

| Phase | Activity                                                          |
| ----- | ----------------------------------------------------------------- |
| T0    | Suspicious authentication activity identified                     |
| T1    | HTTP POST requests targeting Joomla administrator portal observed |
| T2    | Primary attacking source identified                               |
| T3    | Target web server identified                                      |
| T4    | Authentication requests reviewed                                  |
| T5    | Administrative username targeting confirmed                       |
| T6    | Automated tooling indicators identified                           |
| T7    | Brute-force activity validated                                    |

---

## 7) Indicators of Interest

### ▶ 7.1) Network Indicators

**Source IP**

```text
23.22.63.114
```

**Destination IP**

```text
192.168.250.70
```

---

### ▶ 7.2) Application Indicators

**Authentication Endpoint**

```text
/joomla/administrator/index.php
```

**HTTP Method**

```text
POST
```

---

### ▶ 7.3) User-Agent Indicators

```text
Python-urllib/2.7
```

---

### ▶ 7.4) Account Targeting Indicators

**Observed Username**

```text
admin
```

---

### ▶ 7.5) IOC Limitations

While the indicators identified during this investigation are high-confidence within the available dataset, source IP addresses, usernames, and User-Agent strings can be modified by attackers. Detection efforts should prioritize behavioral indicators such as repeated failed authentication attempts and credential guessing patterns.

---

## 8) Case Determination

**Final Determination:**

Confirmed brute-force password guessing campaign targeting the Joomla administrative login portal hosted on `imreallynotbatman.com`.

Evidence supports the conclusion that an external actor systematically attempted to obtain administrative access through automated authentication abuse. Analysis identified repeated credential submissions, scripted request generation, and sustained targeting of the administrator account.

Within the scope of available evidence, successful authentication and post-authentication activity could not be confirmed.

---

## 9) Recommended Follow-Ups (Case Closure Actions)

### ▶ 9.1) Immediate Actions

* Review authentication telemetry for successful logins associated with the targeted account
* Reset administrator credentials if compromise is suspected
* Implement account lockout protections
* Apply rate limiting to authentication endpoints

### ▶ 9.2) Hardening

* Require multi-factor authentication for administrative accounts
* Restrict administrative interface exposure where possible
* Implement web application firewall protections
* Monitor excessive authentication failures

### ▶ 9.3) Detection Opportunities

* Alert on repeated failed authentication attempts
* Alert on high-volume POST requests targeting authentication portals
* Monitor administrative account targeting
* Alert on authentication activity originating from scripted User-Agent strings

---

## 10) Supporting Reports (In This Folder)

* `investigation-walkthrough.md` — Detailed analyst workflow and evidence validation
* `incident-summary.md` — Executive-level incident overview
* `MITRE-ATTACK-mapping.md` — ATT&CK technique mapping and justification
* `images/` — Investigation screenshots and supporting evidence
* `README.md` — Investigation overview and repository navigation

---

## 11) MITRE ATT&CK Mapping

### ▶ 11.1) Technique Mapping

* **Credential Access — Brute Force (T1110)**
* **Credential Access — Password Guessing (T1110.001)**

### ▶ 11.2) MITRE ATT&CK Mapping (Table View)

| Tactic            | Technique                         | Description                                                   |
| ----------------- | --------------------------------- | ------------------------------------------------------------- |
| Credential Access | **Brute Force (T1110)**           | Repeated authentication attempts against a login portal       |
| Credential Access | **Password Guessing (T1110.001)** | Systematic password testing against the administrator account |

---
