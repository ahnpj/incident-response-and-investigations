# Incident Summary — Web Server Defacement Investigation (Malicious File Upload Exploitation and Web Shell Deployment)

## Overview

This incident involved a multi-stage compromise of a public-facing web server hosting a Joomla content management system (CMS), resulting in public website defacement. The attacker conducted automated reconnaissance and vulnerability scanning, performed credential brute-force attacks against the Joomla administrative interface, uploaded and executed a malicious payload, established outbound communication with attacker-controlled infrastructure, and modified site content to display defacement material retrieved from an external source.

The incident demonstrates a complete web-application-to-host intrusion lifecycle and highlights how correlated network, application, IDS, and host telemetry can be used to reconstruct attacker behavior end-to-end.

---

## What Happened

This section summarizes the confirmed attacker actions that led to public defacement. A reconstructed timeline of attacker behavior and business impact is documented in **`case-report.md`**, while detailed analyst workflow, Splunk queries, and investigative pivots are documented in **`investigation-walkthrough.md`**.

Based on correlated telemetry, the following attack sequence was confirmed:

- **Automated reconnaissance and vulnerability scanning** against the web server using tooling consistent with the Acunetix scanner, including malformed HTTP headers and exploit probes detected by Suricata IDS.
- **Targeting of Joomla administrative endpoints**, specifically repeated requests to `/joomla/administrator/index.php`, indicating intent to obtain authenticated access to the CMS.
- **Credential brute-force activity** using repeated HTTP POST requests containing different username and password combinations extracted from form submission data.
- **Successful administrative authentication** using valid credentials (`admin:batman`) originating from external infrastructure previously associated with scanning activity.
- **Malicious file upload to the web server**, including executable payloads such as `3791.exe`, delivered through authenticated CMS functionality.
- **Host-level execution of the uploaded payload**, confirmed via Sysmon process creation telemetry shortly after file upload.
- **Outbound communication to attacker-controlled infrastructure**, including retrieval of external resources hosted on domains associated with the attacker.
- **Public defacement of website content**, achieved by modifying templates or content to load attacker-hosted imagery that replaced legitimate site content.

This sequence confirms that the defacement was not the result of a single vulnerability exploit, but rather a chained intrusion involving credential compromise, malware execution, and application-layer modification.

---

## How It Was Detected

This section describes the telemetry sources that revealed the intrusion and how detection signals emerged across multiple layers of the environment.

The investigation relied on correlation across:

- **Suricata IDS alerts**, which flagged exploit probes, malformed HTTP headers, and scanner signatures associated with automated vulnerability assessment.
- **HTTP application logs (`stream:http`)**, which revealed repeated POST requests to Joomla administrative login endpoints and included extractable credential attempts in form data.
- **Firewall and UTM telemetry (`fortigate_utm`)**, which validated outbound communication from the web server to external infrastructure following compromise.
- **Host-based telemetry (Sysmon)**, which confirmed execution of attacker-uploaded binaries on the server.

Early detection signals appeared during reconnaissance and scanning phases, but escalation to confirmed incident occurred only after authentication abuse, malware execution, and outbound connections were correlated. No single alert fully described the intrusion; confidence was achieved through multi-source correlation rather than isolated indicators.

---

## Scope of Compromise

This section defines the systems and assets confirmed to be affected based on available telemetry.

**In-scope compromised asset:**

- Web server hosting `imreallynotbatman.com`
- IP address: `192.168.250.70`
- Joomla CMS administrative interface and hosted web content

**Observed compromise activity included:**

- Unauthorized administrative access to the Joomla application
- Execution of attacker-controlled code on the host
- Modification of site content to display defacement material

**Not observed within scope:**

- Lateral movement to other systems
- Database compromise
- Infrastructure-wide persistence mechanisms

Scope determinations are based on review of authentication logs, firewall telemetry, and host execution events. While no evidence of lateral movement was observed, the presence of malware execution confirms full compromise of the web server host.

---

## Impact Assessment

This section summarizes the business and technical impact of the incident. Detailed technical impact and evidence references are documented in **`case-report.md`**, while specific artifacts are cataloged in **`detection-artifact-report.md`**.

**Confirmed impacts included:**

- Public-facing website defacement, resulting in reputational damage
- Loss of integrity of hosted web content
- Unauthorized execution of malicious code on production infrastructure
- Exposure of administrative credentials

While data exfiltration was not confirmed, the ability to execute arbitrary code and communicate with external infrastructure represents a significant security breach and potential risk to sensitive backend systems.

---

## Response Status

This section summarizes the status of response actions as represented within the lab scenario. Detailed remediation steps and response sequencing are documented in **`incident-response-report.md`**.

For the purposes of this investigation:

- The incident was fully analyzed and scoped using available telemetry.
- Remediation actions such as credential resets, malware removal, and system restoration were not executed within the lab environment.
- Response actions were documented as recommended procedures rather than performed actions.

In a real-world scenario, this incident would require immediate containment, credential revocation, server isolation, malware eradication, and system restoration from trusted backups.

---

## Root Cause Summary

This section highlights the primary contributing factors that enabled the compromise.

The investigation identified the following root causes:

- **Weak administrative credential controls** on the Joomla CMS, enabling successful brute-force authentication.
- **Lack of rate limiting or account lockout mechanisms** on the administrative login endpoint.
- **Insufficient monitoring of file uploads and executable creation** within web directories.
- **Absence of outbound network restrictions** preventing compromised servers from communicating with attacker-controlled infrastructure.

These weaknesses allowed the attacker to progress from reconnaissance to full host compromise without triggering early containment.

---

## Next Steps and Defensive Priorities

This section outlines where defenders should focus improvement efforts following this incident.

A high-level summary of defensive gaps is documented in the investigation walkthrough under **Detection and Hardening Opportunities**. Detailed and actionable controls are documented in the standalone report: **`detection-and-hardening-recommendations.md`**.

Priority improvement areas include:

- Strengthening CMS authentication controls and enforcing MFA
- Implementing WAF protections for administrative endpoints
- Monitoring file uploads and executable creation within web roots
- Enforcing outbound network filtering for server systems
- Improving correlation between IDS, HTTP, and host telemetry

Detection strategies and preventive controls aligned to these recommendations are designed to interrupt similar attack chains earlier in the lifecycle.

---

## Related Documentation

- `investigation-walkthrough.md` — step-by-step Splunk queries and analyst pivots  
- `case-report.md` — reconstructed attacker timeline and impact validation  
- `MITRE-ATT&CK-mapping.md` — technique classification across intrusion stages  
- `detection-artifact-report.md` — network, web, and host-based indicators  
- `incident-response-report.md` — containment, eradication, and recovery procedures  
- `detection-and-hardening-recommendations.md` — long-term security improvements  

Together, these documents provide a complete incident investigation package aligned with SOC workflows and professional incident documentation standards.
