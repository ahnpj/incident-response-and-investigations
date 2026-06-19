# Joomla Administrator Brute-Force Investigation

**Category:** Web Application Compromise
**Primary Attack Surface:** Joomla administrative authentication portal
**Tactics Observed:** Credential Access
**Primary Data Sources:** HTTP Request Logs, Web Application Telemetry, Authentication Form Submission Data

---

### Overview

This investigation analyzes a brute-force password guessing campaign targeting the Joomla administrative login portal hosted on `imreallynotbatman.com`.

The analysis focuses on reconstructing attacker behavior using HTTP request telemetry collected within Splunk. By reviewing authentication requests, source attribution, destination targeting, submitted credentials, and client metadata, the investigation validates that an external actor systematically attempted to obtain administrative access through automated password guessing.

> 👉 **Follow the investigation walkthrough first**</br>
> Begin with `investigation-walkthrough.md` to see how I identified the attack, validated source attribution, reviewed authentication requests, and confirmed brute-force behavior step by step.

> 👉 **Review findings and conclusions**</br>
> Move to `case-report.md` and `incident-summary.md` to understand what occurred, what evidence supported the findings, and how the activity was ultimately classified.

> 👉 **Review supporting evidence**</br>
> Examine the screenshots contained within the `images/` directory to see the exact Splunk searches, event analysis, field review, and credential submission evidence used throughout the investigation.

> 👉 **Review defensive takeaways**</br>
> Finish with `MITRE-ATTACK-mapping.md` and supporting documentation to understand how the observed behavior maps to known adversary techniques and where detection opportunities were identified.

> 👉 **See what each investigation file contains in full detail**</br>
> For a complete breakdown of every standard file in an investigation folder, including its purpose and role in the overall investigation package, see the **[Repository Structure & Supporting Documents](#repository-structure--supporting-documents)** section below.

This investigation demonstrates how an analyst:

* Identifies suspicious authentication activity targeting a web application
* Uses Splunk to isolate malicious HTTP POST requests
* Attributes activity to a specific external source
* Identifies the targeted internal asset
* Reviews submitted authentication parameters
* Detects indicators of automated tooling
* Validates brute-force password guessing activity
* Documents findings using a structured investigation methodology

---

### What This Investigation Covers

This case analyzes HTTP request telemetry associated with authentication attempts against a Joomla administrative login portal.

The investigation begins with identification of suspicious POST requests targeting the Joomla administrator endpoint. Analysis then pivots into source attribution, destination asset identification, review of submitted authentication parameters, and examination of attacker tooling characteristics.

The investigation ultimately confirms that a single external source generated the overwhelming majority of authentication attempts and repeatedly submitted credentials against the administrative account using automated tooling.

Rather than focusing on malware, exploitation, or host compromise, the investigation demonstrates how web application telemetry alone can be used to identify and validate credential attack activity.

---

### How to Navigate This Investigation

This case is documented across multiple reports designed to mirror real-world incident documentation practices.

If you want to follow the investigation from beginning to end, start with: **`investigation-walkthrough.md`**

---

### Repository Structure & Supporting Documents

All investigation outputs are separated into focused reports aligned with common incident response and security operations workflows.

| File / Folder                  | Purpose                                            | Contents and Focus                                                                                                                                                                            |
| ------------------------------ | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `investigation-walkthrough.md` | Step-by-step analyst investigation process.        | Documents initial detection, source attribution, destination identification, HTTP request analysis, credential review, automated tooling indicators, and brute-force validation using Splunk. |
| `images/`                      | Visual evidence supporting investigative findings. | Contains screenshots of Splunk searches, event review, source attribution, destination analysis, credential submissions, and supporting evidence used throughout the investigation.           |
| `case-report.md`               | Formal technical case documentation.               | Summarizes evidence reviewed, findings, indicators of interest, investigation scope, timeline, and final determination.                                                                       |
| `incident-summary.md`          | Executive-level incident overview.                 | Provides a concise summary of attacker behavior, investigation outcome, impact assessment, and key findings.                                                                                  |
| `MITRE-ATTACK-mapping.md`      | ATT&CK technique mapping and justification.        | Maps observed credential attack behavior to MITRE ATT&CK techniques and explains supporting evidence.                                                                                         |
| `README.md`                    | Investigation overview and navigation guide.       | Provides context, scope, repository structure, and guidance for reviewing the investigation.                                                                                                  |

---

### Environment, Data Sources, and Tools

This investigation focuses on application-layer authentication activity and web request telemetry rather than host-level compromise or malware execution.

#### Environment and Investigation Scope (At a Glance)

| Area                             | Details                                                                       |
| -------------------------------- | ----------------------------------------------------------------------------- |
| **Environment Type**             | Joomla web application                                                        |
| **Affected Assets**              | Administrative authentication interface                                       |
| **Investigation Platform**       | Splunk Enterprise                                                             |
| **Dataset**                      | BOTSv1                                                                        |
| **Primary Platforms / Services** | Joomla CMS, HTTP authentication workflow, Splunk search and analysis platform |
| **Investigation Focus**          | Validate brute-force activity targeting the Joomla administrator account      |

#### Data Sources, Evidence, and Analysis Techniques

| Area                               | Details                                                                                                                     |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **Primary Telemetry Sources**      | `stream:http` events collected within Splunk                                                                                |
| **Authentication Evidence**        | HTTP POST requests targeting the Joomla administrator login page                                                            |
| **Source Attribution Evidence**    | Source IP analysis and event frequency review                                                                               |
| **Target Identification Evidence** | Destination IP analysis and URI review                                                                                      |
| **Credential Evidence**            | Submitted form parameters contained within HTTP request data                                                                |
| **Automation Indicators**          | Python-based User-Agent strings and repetitive authentication activity                                                      |
| **Splunk Correlation Techniques**  | Source IP analysis, field review, request filtering, timestamp-based pivots, and form data inspection                       |
| **Manual Analysis Techniques**     | Event review, credential inspection, timeline reconstruction, and behavioral analysis                                       |
| **Operational Workflow Context**   | Demonstrates how web application telemetry can be used to validate credential attacks without requiring host-level evidence |

This investigation demonstrates how HTTP request telemetry can be leveraged to identify, validate, and document brute-force authentication attacks targeting publicly accessible web applications.

---

### Intended Use

This investigation demonstrates structured web application attack analysis using Splunk and HTTP request telemetry.

The investigation reflects how analysts identify suspicious authentication activity, validate attacker behavior, perform evidence-driven analysis, and document findings using repeatable incident response methodologies.

---

### Relevance to Security Operations

Brute-force attacks remain one of the most common methods used to obtain unauthorized access to web applications and administrative interfaces.

This investigation demonstrates how defenders can identify authentication abuse, attribute activity to specific sources, recognize indicators of automated tooling, and validate credential attack activity using only web application telemetry.

The techniques demonstrated throughout this investigation support earlier detection of authentication abuse and improved protection of administrative interfaces exposed to the internet.

---

If you are reviewing this as part of my cybersecurity portfolio, this investigation demonstrates structured analysis of web application authentication activity, evidence-based validation of credential attack behavior, and professional incident documentation aligned with SOC and incident response workflows.
