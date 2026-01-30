# Endpoint Cryptominer Infection Investigation (Suspicious Process Execution and Resource Abuse)

## Executive Summary
A security monitoring alert was generated for an anomalous process execution identified by the SIEM as `cudominer.exe`. The alert required further investigation to determine whether the execution represented benign user behavior or malicious activity. By correlating process creation events with user and host data, the activity was evaluated and ultimately classified as a true positive consistent with cryptocurrency mining behavior.

---

## Incident Scope
This investigation focused on a single automatically generated SIEM alert associated with suspicious process execution. The scope was limited to the endpoint, user account, and log data directly related to the alert event. The primary objective was to validate the alert by identifying the responsible process, attributing execution to a specific user and host, and determining whether the activity met the criteria for malicious classification. Analysis beyond the originating host, including lateral movement or broader environmental impact, was outside the scope of this investigation.

---

## Environment, Evidence, and Tools
The investigation was conducted within a Windows domain environment identified as `cybertees.local`. Evidence reviewed consisted of SIEM alert metadata and correlated Windows Security Event Logs, specifically process creation events generated under Event ID 4688. These data sources provided visibility into executable names, execution paths, user context, and host attribution. Analysis was performed using the SIEM dashboard and its built-in log correlation and filtering capabilities.

---

## Investigative Questions
The investigation was guided by a set of focused questions intended to validate the alert and determine its significance. These questions included identifying the process responsible for triggering the alert, attributing execution to a specific user account and host, evaluating whether the execution context aligned with known malicious behaviors, and determining whether the alert should be classified as a true positive or false positive.

---

## Investigation Timeline
The investigation began when the SIEM generated an alert indicating suspicious process activity. Initial review of alert metadata led to identification of the flagged executable. Subsequent analysis of correlated process creation events allowed attribution to a specific user account and host. Finally, the execution context and detection logic were reviewed together to reach a classification decision.

---

## Investigation Walkthrough

### Suspicious Process Identification
The investigation began with a review of the SIEM dashboard to understand the nature of the alert and identify the process responsible for triggering detection. The alert highlighted an abnormal executable associated with behavior commonly linked to cryptocurrency mining. This initial review established `cudominer.exe` as the focal point of the investigation.

<p align="left">
  <img src="images/siem-foundational-figure.01-alert.png" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 1: Suspicious process in SIEM dashboard</em>
</p>

The process name immediately stood out due to its similarity to known mining tools and its deviation from standard application naming conventions typically observed in legitimate environments.

### User and Host Attribution
After identifying the suspicious executable, correlated event logs were examined to determine where and by whom the process was executed. Process creation telemetry revealed that `cudominer.exe` was launched under the context of the user account `Chris.Fort` on the host `HR_02`. This correlation confirmed both user attribution and endpoint involvement. Execution from a user-writable temporary directory is atypical for legitimate software and reinforced suspicion of malicious intent.

<p align="left">
  <img src="images/siem-foundational-figure.02-event-log.png" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="1000"><br>
  <em>Figure 2 – Event Log Correlation for Suspicious Process</em>
</p>

Further inspection of execution details showed that the process was launched from a temporary directory rather than a standard application path. The executable path observed was: `C:\Users\Chris.Fort\temp\cudominer.exe`

### Detection Rule Review
To ensure the alert fired as expected, the SIEM correlation rule responsible for the detection was reviewed. The rule monitors Windows process creation events and evaluates executable names for keywords commonly associated with cryptocurrency mining activity, including variations of `miner` and `crypt`.

<p align="left">
  <img src="images/siem-foundational-figure.03-rule.png" 
       alt="SIEM alert" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="600"><br>
  <em>Figure 3 – SIEM Rule Used to Detect Potential CryptoMiner Activity</em>
</p>

The execution of `cudominer.exe` satisfied the rule’s detection criteria, confirming that the alert was triggered intentionally and functioned as designed.

---

## Findings Summary

Analysis confirmed that the process `cudominer.exe` was executed on a Windows endpoint within the domain environment. The execution was attributed to the user account `Chris.Fort` on the host `HR_02`. The process originated from a non-standard, user-writable directory and matched detection logic designed to identify cryptocurrency mining behavior. Based on these findings, the alert was correctly classified as a true positive.

**Detailed Evidence Reference:**  
For a full, artifact-level breakdown of logs, alerts, and forensic indicators that support these findings — including where each artifact was identified during the investigation — see: **`detection-artifact-report.md`**

---

## Defensive Takeaways

This investigation highlights that SIEM alerts represent starting points for analysis rather than definitive conclusions. Accurate classification depends on correlating execution context with user and host attribution. Additionally, execution path analysis can provide valuable insight into whether an executable is likely legitimate or malicious. Even straightforward alerts benefit from a structured investigative approach to support confident decision-making.

---

## Artifacts Identified

The investigation identified several artifacts supporting the final determination. These included the suspicious executable `cudominer.exe`, the associated user account `Chris.Fort`, the affected host `HR_02`, the execution path `C:\Users\Chris.Fort\temp\cudominer.exe`, and the SIEM correlation rule designed to detect mining-related processes.

**Detailed Evidence Reference:**  
For a full, artifact-level breakdown of logs, alerts, and forensic indicators that support these findings — including where each artifact was identified during the investigation — see: **`detection-artifact-report.md`**

---

## Detection and Hardening Opportunities

This section summarizes high-level detection and hardening opportunities observed during the investigation. For detailed, actionable recommendations — including specific logging gaps, detection logic ideas, and configuration improvements — see: **`detection-and-hardening-recommendations.md`**

### Containment Actions (Recommended)
These actions focus on limiting host-level impact and preventing further resource abuse.

- Isolate the affected endpoint (`HR_02`) from the network to prevent additional malicious activity.
- Terminate the suspicious process (`cudominer.exe`) and remove the executable from disk.
- Reset credentials for the associated user account (`Chris.Fort`) as a precaution.
- Perform a targeted scan of the endpoint for additional unauthorized executables or persistence mechanisms.

### Eradication & Hardening Recommendations
These recommendations address execution pathways leveraged by the miner.

- Restrict execution from user-writable directories such as `%TEMP%` and `%APPDATA%`.
- Implement application allowlisting to prevent unauthorized binaries from executing.
- Harden endpoint protections to prevent commodity mining tools from running.
- Establish baselines for expected process names and execution paths in the environment.

### Detection & Monitoring Recommendations
These detections focus on early identification of unauthorized execution.

- Alert on process execution from user-writable directories.
- Alert on executable names containing mining-related keywords (e.g., `miner`, `crypt`).
- Enrich SIEM alerts with automatic user and host attribution to reduce triage time.
- Monitor for sustained high CPU or resource utilization correlated with unknown processes.

### Response Validation & Follow-Up (Optional)
- Re-scan the affected endpoint to confirm removal of the malicious executable and absence of additional unauthorized binaries.
- Review post-containment process execution logs to ensure no further mining-related processes are launched.
- Validate that endpoint and SIEM detections would trigger on execution from user-writable directories.
- Monitor CPU and resource utilization metrics to confirm return to normal baseline behavior.
- Perform a short-term review of nearby hosts for similar process execution patterns or indicators.


---

## MITRE ATT&CK Mapping

The following mappings connect observed behaviors to MITRE ATT&CK techniques and cite the specific evidence identified during SIEM alert review and process execution analysis. Mappings are based on directly observed activity and artifacts within scope.

- **Execution — User Execution (T1204):**  
  A suspicious executable (`cudominer.exe`) was launched under a user context, as observed in process creation telemetry that triggered the SIEM alert.

- **Impact — Resource Hijacking (T1496):**  
  The executed process exhibited behavior consistent with cryptocurrency mining, indicating unauthorized consumption of system resources for attacker benefit.

### MITRE ATT&CK Mapping (Table View)

| Tactic | Technique | Description |
|------|-----------|-------------|
| Execution | **User Execution (T1204)** | A suspicious executable was launched under a user context, confirmed through process creation events and SIEM alert data. |
| Impact | **Resource Hijacking (T1496)** | Unauthorized cryptocurrency mining activity resulted in sustained consumption of host resources. |

**Note:** This section provides a high-level summary of observed ATT&CK tactics and techniques. For evidence-backed mappings tied to specific artifacts, timestamps, and investigation steps, see: **`mitre-attack-mapping.md`**



