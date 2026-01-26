# MITRE ATT&CK Mapping - Web Application Authentication Compromise Investigation (Brute-Force Attempts and Account Compromise Detection)

This document maps attacker behaviors observed during this investigation to MITRE ATT&CK tactics and techniques using direct evidence from web application authentication logs and HTTP request metadata.

All mappings are based on confirmed activity reconstructed during analysis rather than inferred attacker intent or assumed tooling.

The purpose of this mapping is to support standardized incident classification, detection coverage validation, and alignment with threat modeling frameworks commonly used by security operations teams.

---

## How This Mapping Was Performed

Techniques were mapped by reviewing:

- Authentication success and failure events recorded by the application
- Source IP address patterns across repeated login attempts
- Username targeting patterns over time
- Endpoint paths associated with authentication activity
- Logged credential-handling fields captured during authentication

Each technique below references the investigative pivots and artifacts that supported classification.

---

## MITRE ATT&CK Mapping (Narrative View)

### (1) Credential Access (Brute Force)

#### (1A) Brute Force (T1110)

**Observed Behavior:**  
A high volume of failed authentication attempts were observed against the `/api/login` endpoint from a single external IP address over a short time window. During investigation, this activity was identified by filtering authentication logs for repeated failures tied to the same source IP and endpoint path, indicating automated credential guessing rather than normal user behavior.

**Why This Maps to ATT&CK:**  
ATT&CK defines brute force as repeated attempts to guess credentials through trial and error. The observed high-frequency failures against the authentication endpoint align directly with this technique.

**Evidence Sources and Attribution:**
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Authentication Outcomes | Repeated `failure` results in application authentication logs | Indicates unsuccessful login attempts |
| Source IP | Consistent source IP across multiple attempts | Links failures to same attacking host |
| Target Endpoint | Repeated targeting of `/api/login` endpoint | Confirms focused attack against authentication API |

#### (1B) Password Spraying (T1110.003)

**Observed Behavior:**  
Authentication attempts were distributed across multiple usernames rather than focusing on a single account, indicating a strategy to test common credentials across many users. The investigation showed attempts against both invalid and valid usernames before a successful authentication event occurred, consistent with spraying behavior rather than targeted brute force against one account.

**Why This Maps to ATT&CK:**  
Password spraying is characterized by testing a small number of passwords across many accounts to avoid lockouts and detection. The observed wide distribution of username targets supports this classification.

**Evidence Sources and Attribution:** 
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Username Diversity | Many distinct usernames targeted from same source IP | Indicates automated guessing or spray behavior |
| Invalid Accounts | Attempts against non-existent accounts | Supports enumeration or broad targeting |
| Valid Accounts | Follow-on attempts against known valid users | Shows refinement after discovery phase |
| Client Metadata | Consistent client headers and identifiers | Links attempts to same automated tooling |

#### (1C) Unsecured Credentials (T1552)

**Observed Behavior:**  
Credential material was logged in a reversible format within authentication logs. The investigation identified a `hashed_password` field whose value remained consistent across authentication attempts and was confirmed to be Base64-encoded, allowing recovery of the plaintext password. This confirmed that credentials were exposed by the application logging process itself.

**Why This Maps to ATT&CK:**  
ATT&CK classifies exposure of recoverable credentials in files or logs as unsecured credential storage. Logging reversible credential material directly supports this technique classification.

**Evidence Sources and Attribution:**  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Log Fields | Authentication logs containing `hashed_password` values | Identifies sensitive credential handling |
| Value Reuse | Repeated identical encoded values across events | Indicates same credential reused |
| Decoding Result | Successful Base64 decoding reveals original password | Confirms reversible credential exposure |


### Discovery

#### (2) Account Discovery (T1087)

**Observed Behavior:**  
Authentication attempts included usernames that were not valid accounts, followed by repeated attempts against confirmed legitimate users. This pattern was identified by comparing attempted usernames against known valid accounts and observing a shift from invalid names to legitimate user targets.

**Why This Maps to ATT&CK:**  
Account discovery includes attempts to identify valid users within an environment. Using authentication probing to determine which usernames exist is a common discovery technique and aligns with ATT&CK’s definition.

**Evidence Sources and Attribution:**
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Invalid Usernames | Authentication logs containing invalid usernames | Indicates discovery of valid account set |
| Follow-on Attempts | Subsequent attempts against valid accounts | Shows progression from enumeration to targeting |
| Temporal Pattern | Enumeration precedes successful access | Establishes attacker workflow sequencing |



### Initial Access / Persistence

#### (3) Valid Accounts (T1078)

**Observed Behavior:**  
A successful authentication occurred after repeated failures, and the same credentials were later reused from a different source IP address without additional failed attempts. This indicates that valid credentials were obtained and operationalized rather than a single anomalous login event.

**Why This Maps to ATT&CK:**  
ATT&CK defines Valid Accounts as use of legitimate credentials to access systems or services. Continued access using the same credentials from multiple sources confirms credential compromise rather than mis-typed attempts.

**Evidence Sources and Attribution:**  
| Field | Value | Investigative Use |
|--------|--------|------------------|
| Invalid Usernames | Authentication logs containing invalid usernames | Indicates discovery of valid account set |
| Follow-on Attempts | Subsequent attempts against valid accounts | Shows progression from enumeration to targeting |
| Temporal Pattern | Enumeration precedes successful access | Establishes attacker workflow sequencing |



---

## MITRE ATT&CK Mapping (Table View)

| Tactic | Technique ID | Technique Name | Evidence Summary | Evidence Source |
|--------|--------------|----------------|------------------|-----------------|
| Credential Access | T1110 | Brute Force | High-rate failed logins from single IP against `/api/login` | Application auth logs |
| Credential Access | T1110.003 | Password Spraying | Many usernames targeted from same source before success | Authentication logs |
| Discovery | T1087 | Account Discovery | Invalid usernames tested prior to targeting valid users | Username analysis |
| Initial Access / Persistence | T1078 | Valid Accounts | Successful login followed by credential reuse from new IP | Auth logs, IP correlation |
| Credential Access | T1552 | Unsecured Credentials | Reversible Base64-encoded password logged by application | Auth log fields |

This table provides a condensed reference suitable for reporting, detection validation, and technique tracking across multiple investigations.

---

## Detection and Control Relevance

Mapping behaviors to MITRE ATT&CK supports defensive operations by:

- Highlighting detection opportunities for brute force and spraying at the application layer  
- Reinforcing correlation of failure-to-success authentication sequences  
- Identifying credential exposure risks within application logging pipelines  
- Supporting prioritization of rate limiting and anomaly detection on authentication endpoints  

Detection opportunities and preventive control recommendations associated with these techniques are documented in:

- `detection-artifact-report.md`  
- `detection-and-hardening-recommendations.md`

---

## Notes and Assumptions

- Techniques are mapped solely based on behaviors confirmed in application logs reviewed during this investigation.
- No malware delivery, exploit activity, or endpoint compromise was observed within scope.
- Mapping avoids attribution to specific attacker tooling or campaigns and focuses strictly on observable behavior.

This mapping reflects how ATT&CK is commonly applied during application-layer authentication abuse investigations using log-driven reconstruction workflows.

