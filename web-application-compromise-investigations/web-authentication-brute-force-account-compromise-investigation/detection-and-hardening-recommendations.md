# Detection and Hardening Recommendations — Web Application Authentication Compromise Investigation (Brute-Force Attempts and Account Compromise Detection)

## Purpose and Scope

This report documents detailed preventive controls and detection engineering recommendations based directly on behaviors confirmed during the investigation of web application authentication abuse that resulted in account compromise and credential reuse.

Recommendations in this document are derived from specific findings documented in:

- `web-application-authentication-abuse-investigation.md` (analyst workflow, log pivots, evidence validation, and findings)
- `case-report.md` (reconstructed attacker activity timeline and business impact framing)
- `MITRE-ATT&CK-mapping.md` (technique classification and behavioral context)
- `detection-artifact-report.md` (authentication, enumeration, reuse, and credential exposure artifacts)

**High-Level Summary Reference**  
A condensed overview of defensive gaps is provided in `web-application-authentication-abuse-investigation.md` → **Detection and Hardening Opportunities**.  
This report expands those observations into a standalone, detailed engineering and policy plan tied to the confirmed attack sequence (enumeration → brute force → success → secondary IP reuse → post-auth activity).

---

## Summary of Defensive Control Failures Observed

This section summarizes the primary control gaps that allowed the attacker to progress from automated login attempts to confirmed compromise and continued application use.

Based on investigation findings, the following failures were confirmed:

- **Authentication abuse was not throttled or blocked quickly enough.** Repeated failures against `/api/login` from `198.51.100.100` were observed at scale (Finding 1; Figure 1), indicating missing or ineffective rate limiting and/or lockout controls.
- **Account enumeration was possible.** Attempts against non-existent usernames (Finding 3; Figure 3) suggest the attacker could test names without meaningful friction.
- **Privileged accounts were not protected by MFA.** Successful login for `webadmin` without additional challenge (Finding 5; Figure 5) indicates credentials alone were sufficient to authenticate.
- **Credential reuse from alternate infrastructure went unchallenged.** A second login from `198.23.200.101` occurred minutes after compromise (Finding 6; Figure 6) without additional verification.
- **Critical credential-handling weakness existed in logging design.** The application logged a Base64-encoded value in the `hashed_password` field which decoded to plaintext `webadmin1234` (Finding 8; Figure 8). This represents a systemic design flaw and high-risk credential exposure condition.
- **Behavioral correlation was missing.** The environment lacked a correlation rule to elevate “failures → success → rapid IP change” as a high-fidelity compromise pattern.

As reconstructed in `case-report.md`, these gaps enabled the attacker to:

1. Probe usernames and attempt repeated logins against `/api/login`.
2. Identify valid targets (`webadmin`, `websitemanager`, `ftp`) (Finding 4).
3. Successfully authenticate as `webadmin` (Finding 5).
4. Reuse the compromised credential from a different IP shortly after (Finding 6).
5. Continue interacting with the application post-authentication (Finding 7).

---

## Authentication Controls Hardening

This section focuses on reducing the likelihood that automated login abuse can succeed, even when attackers can generate high-volume traffic.

### Implement Strong Rate Limiting on `/api/login`

**Evidence from Investigation:**  
Repeated failed authentication attempts concentrated on `/api/login` (Finding 7) and were heavily sourced from `198.51.100.100` (Finding 1). This indicates the endpoint was not protected by an effective request-throttling control during the attack window.

**Recommendation:**

- Apply per-IP, per-account, and global throttles for authentication endpoints.
- Use progressive delays (exponential backoff) after repeated failures.
- Enforce a maximum number of login attempts per time window, with increasing cooldown periods.

**Why This Matters:**  
Rate limiting increases attacker cost and reduces the probability of brute-force success, especially when the attacker is limited to a single host or a small infrastructure pool.

### Implement Account Lockout / Step-Up Authentication Thresholds

**Evidence from Investigation:**  
The attacker performed many failures against valid accounts (Finding 4) without triggering a meaningful deterrent mechanism.

**Recommendation:**

- Lock accounts temporarily after a configured number of failures.
- Prefer step-up verification (CAPTCHA, email OTP, push confirmation) for privileged accounts rather than hard lockouts that can be abused for denial-of-service.
- Apply stricter controls to administrative accounts such as `webadmin`.

**Why This Matters:**  
Lockout and step-up controls prevent credential guessing from running indefinitely and help identify automated abuse early.

### Enforce MFA for Privileged Accounts

**Evidence from Investigation:**  
`webadmin` successfully authenticated without a second factor (Finding 5), indicating credential-only access was possible.

**Recommendation:**

- Require MFA for:
  - Admin accounts (`webadmin`)
  - Accounts with elevated privileges (application managers, service users)
- Consider phishing-resistant MFA for administrative access if supported.

**Why This Matters:**  
MFA breaks the attacker’s dependency on “password-only” access, making brute force and credential stuffing far less effective.

---

## Account Enumeration and Username Targeting Mitigations

This section focuses on reducing attacker ability to enumerate or validate usernames during the pre-compromise phase.

### Normalize Authentication Failure Responses

**Evidence from Investigation:**  
The attacker attempted numerous non-existent usernames (Finding 3), suggesting enumeration behavior as part of the attack strategy.

**Recommendation:**

- Ensure login responses do not differ for:
  - Invalid username
  - Incorrect password
- Standardize response messages, response codes, and latency where feasible.

**Why This Matters:**  
Enumeration reduces attacker noise and increases targeting efficiency. Removing feedback forces attackers to guess blindly.

### Monitor and Rate Limit Multi-Username Login Attempts

**Evidence from Investigation:**  
Multiple distinct usernames were tested from the same source (Finding 3), followed by concentrated targeting of valid users (Finding 4).

**Recommendation:**

- Add detection thresholds for:
  - Many usernames attempted from one IP in short time window
- Trigger bot challenges when enumerations are detected.

**Why This Matters:**  
This blocks the “name discovery” phase before attackers shift to high-value targets.

---

## Credential Handling and Logging Security (Critical)

This section addresses the highest-risk systemic weakness confirmed during investigation: reversible credentials in logs.

### Remove Credential-Like Fields from Authentication Logs

**Evidence from Investigation:**  
The `hashed_password` field contained a Base64-encoded value that decoded to plaintext password `webadmin1234` (Finding 8; Figure 8). This is not a hash and represents credential exposure.

**Recommendation:**

- Immediately remove or redact credential values from logs.
- Ensure authentication logs record only:
  - User identifiers
  - Success/failure outcome
  - Source IP
  - Timestamp
  - Request metadata
- Do not log:
  - Passwords
  - Hashes
  - Encoded password representations

**Why This Matters:**  
If an attacker gains access to logs (via misconfiguration, insider threat, or adjacent compromise), they can bypass brute force entirely by extracting plaintext credentials.

### Adopt Secure Password Storage and Verification Practices

**Evidence from Investigation:**  
The existence of reversible “hashed_password” logging suggests insecure credential handling design.

**Recommendation:**

- Store passwords using strong one-way hashing with salt (industry-standard algorithms).
- Ensure password comparisons occur only against one-way hash outputs.
- Review authentication code paths to confirm secrets are not serialized into logs or debug output.

**Why This Matters:**  
Secure storage and handling reduce credential exposure risk even if logs or databases are compromised.

---

## Detection Engineering Improvements

This section defines behavioral detections directly derived from the confirmed attack sequence.

### Alert on High-Volume Failures Against `/api/login`

**Evidence from Investigation:**  
Failed attempts from `198.51.100.100` spiked against `/api/login` (Findings 1 and 7).

**Recommendation (Detection Logic):**

- Trigger alert when:
  - failures_per_ip_per_5min exceeds threshold
  - endpoint == `/api/login`
- Add enrichment:
  - geolocation/ASN
  - reputation feeds (if available)

**Why This Matters:**  
Provides early warning before compromise occurs.

### Correlate Failures → Success Within Short Time Window

**Evidence from Investigation:**  
Successful authentication for `webadmin` followed repeated failures (Finding 5).

**Recommendation (Correlation Blueprint):**

Trigger high-severity alert when:

1. Account has N failed logins within T minutes  
2. Followed by a success for the same account within T2 minutes  
3. From the same IP or same User-Agent

**Why This Matters:**  
This pattern is a high-confidence indicator of credential guessing success.

### Correlate Success → Rapid Source IP Change (Reuse Detection)

**Evidence from Investigation:**  
A second successful login for `webadmin` occurred at `10:05:20` from `198.23.200.101` shortly after the initial success (Finding 6).

**Recommendation (Correlation Blueprint):**

Trigger critical alert when:

1. Account authenticates successfully from IP A  
2. Within < 10 minutes, same account authenticates from IP B  
3. AND recent failures occurred OR account is privileged

**Why This Matters:**  
Rapid infrastructure switching is common post-compromise behavior and is rare in legitimate admin usage patterns.

### Detect Enumeration Behavior (Invalid Username Bursts)

**Evidence from Investigation:**  
Multiple failed attempts against non-existent usernames occurred (Finding 3).

**Recommendation (Detection Logic):**

- Alert when:
  - distinct_usernames_attempted_per_ip exceeds threshold
  - percentage_invalid_usernames exceeds threshold

**Why This Matters:**  
Detects early-stage enumeration before the attacker narrows onto valid accounts.

---

## Web Application Perimeter and WAF Controls

This section focuses on deploying compensating controls to stop automated abuse at the edge before it hits application auth logic.

### Bot Detection and Challenge Controls

**Evidence from Investigation:**  
Consistent User-Agent string across attempts (Finding 2) suggests automated tooling.

**Recommendation:**

- Add bot detection rules for:
  - repeated User-Agent values
  - high request velocity
  - repeated auth endpoint targeting
- Implement challenges (CAPTCHA / JS challenge) after failure thresholds are met.

**Why This Matters:**  
Reduces load on application and blocks commodity brute-force tooling quickly.

### IP Reputation / ASN-Based Throttling

**Evidence from Investigation:**  
Attack activity concentrated on one IP, then shifted to another for reuse (Finding 6).

**Recommendation:**

- Integrate IP reputation sources if available.
- Apply stricter throttles for:
  - known VPS providers
  - high-risk ASNs
- Do not rely solely on IP blocks (attackers rotate quickly).

**Why This Matters:**  
Improves defense in depth without depending on brittle single-IP blocks.

---

## Monitoring, Visibility, and Operational Improvements

This section addresses telemetry coverage required to confidently detect and investigate similar incidents.

### Ensure Logs Capture Required Fields for Detection

**Evidence from Investigation:**  
The investigation relied on correlating source IP, endpoint, username, timestamps, and User-Agent across multiple findings (Findings 1–7).

**Recommendation:**

Ensure auth/application logs reliably record:

- `timestamp`
- `username`
- `source_ip`
- `request_path`
- `response_code`
- `user_agent`
- session identifier (post-auth)

**Why This Matters:**  
Without these fields, detection engineering cannot reliably implement correlation logic derived from the incident.

### Improve Alert Routing for Privileged Account Events

**Evidence from Investigation:**  
The compromise involved `webadmin`, a privileged account (Findings 4–6).

**Recommendation:**

- Configure escalations for:
  - any suspicious activity involving privileged accounts
- Route alerts to:
  - SOC / on-call security
  - application owners (for rapid remediation)

**Why This Matters:**  
Privileged account compromise has higher blast radius and requires faster response.

---

## Prioritized Recommendations

This table summarizes controls that would most effectively reduce risk based on the behaviors observed in this incident.

| Priority | Area | Recommendation | Evidence Basis |
|---------|------|----------------|----------------|
| Critical | Logging Security | Remove credential-like fields from logs | Base64 password exposure (Finding 8) |
| High | Authentication Hardening | Enforce MFA for privileged accounts | `webadmin` success without MFA (Finding 5) |
| High | Rate Limiting | Throttle `/api/login` with progressive delays | High-volume failures (Finding 1) |
| High | Detection Engineering | Correlate failures → success → rapid IP change | Secondary login reuse (Finding 6) |
| Medium | Enumeration Defense | Normalize auth failures + detect invalid username bursts | Non-existent username attempts (Finding 3) |
| Medium | Perimeter Controls | Bot challenges based on User-Agent/velocity | Automation fingerprint (Finding 2) |
| Low | Governance | Privileged account policy review (least privilege) | High-risk target accounts (Finding 4) |

---

## Closing Observations

This investigation demonstrates how an authentication abuse campaign can progress from enumeration to confirmed compromise and credential reuse within minutes.

As validated in the investigation:

- Automated login failures were sustained against `/api/login` from `198.51.100.100` (Findings 1 and 7).
- High-value valid accounts were targeted (`webadmin`, `websitemanager`, `ftp`) (Finding 4).
- Compromise was confirmed by successful login of `webadmin` at `2023-06-29T10:00:12` (Finding 5).
- Credential reuse was confirmed by a second success from `198.23.200.101` at `2023-06-29T10:05:20` (Finding 6).
- The most critical systemic risk was the discovery of reversible credential logging (Finding 8).

Effective defense therefore requires:

- Strong auth controls (rate limiting, step-up, MFA)
- Enumeration resistance
- High-fidelity correlation detections
- Immediate remediation of credential handling and logging weaknesses

Without these controls, attackers can brute force or recover credentials and reuse them across infrastructure before defenders can respond.
