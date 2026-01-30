# Incident Response Report — Web Application Authentication Compromise Investigation (Brute-Force Attempts and Account Compromise Detection)

### 1) Incident Classification

This section documents how the incident was categorized and prioritized based on confirmed automated authentication abuse, successful credential compromise, and subsequent reuse from a secondary source.

- **Incident Type:** Web Application Compromise Attempt — authentication abuse resulting in account takeover  
- **Severity:** High (validated successful login + credential reuse + credential exposure weakness)  
- **Status:** Contained (credential reset + access controls applied)  
- **Primary Impact Area:** Application authentication integrity and account confidentiality

Classification is based on evidence reconstructed in `case-report.md` and validated in `web-application-authentication-abuse-investigation.md`, including:

- High-frequency failed authentication activity from the primary attacking IP `198.51.100.100` (Finding 1; Figure 1)
- Successful authentication of the privileged account `webadmin` at `2023-06-29T10:00:12` (Finding 5; Figure 5)
- Secondary successful authentication from a different source IP `198.23.200.101` at `2023-06-29T10:05:20` using the same endpoint and User-Agent (Finding 6; Figure 6)
- Evidence that the application logged a reversible Base64-encoded password value (`hashed_password`) which was decoded to plaintext `webadmin1234` (Finding 8; Figure 8)

---

### 2) Detection Trigger

This section describes how the incident was initially identified and why escalation to incident response was required.

Investigation was triggered by abnormal authentication patterns in application logs, including repeated failed logins against multiple usernames within short time intervals and consistent request metadata (same User-Agent string and targeted endpoint).

Escalation to incident response was required once the investigation confirmed **successful authentication** for `webadmin` (Finding 5) and **credential reuse** from a second IP shortly after the first compromise (Finding 6). At that point, the activity was no longer “attempted brute force” — it was a confirmed account takeover event.

For the reconstructed attacker timeline (failed attempts → success → reuse), see `case-report.md` → **Investigation Timeline**. For the analyst’s exact log pivots and validation steps, see `web-application-authentication-abuse-investigation.md`.

---

### 3) Initial Triage Actions

This section outlines the first steps taken to validate malicious activity, identify compromised accounts, and determine scope.

Initial triage focused on answering three questions:

1. **Is this automated abuse or legitimate user error?**  
   Analysts validated the consistency of request metadata (Finding 2: identical User-Agent across attempts) and the volume/pattern of failures from a single source (Finding 1). These characteristics supported automation rather than normal user behavior.

2. **Which accounts were targeted and which were successfully compromised?**  
   Analysts separated failed attempts against **non-existent accounts** (Finding 3; 9 usernames listed) from attempts against **valid accounts** (Finding 4: `websitemanager`, `webadmin`, `ftp`). This narrowed scope to high-value targets and enabled prioritization.

3. **Was there a confirmed successful login and post-login activity?**  
   Analysts pivoted to successful authentication events and confirmed the first successful login of `webadmin` at `2023-06-29T10:00:12` (Finding 5), then identified a second successful login at `2023-06-29T10:05:20` from `198.23.200.101` (Finding 6). This secondary login significantly increased confidence of compromise and suggested attacker-controlled reuse or staging.

Triage also confirmed that all failed and successful authentication activity targeted the same endpoint: `/api/login` (Finding 7; Figure 7). This allowed scoping and response actions to focus on a single authentication surface.

---

### 4) Containment Actions

This section summarizes actions taken to immediately stop attacker access, prevent additional credential guessing, and limit further exposure.

Containment actions prioritized **cutting off attacker access first**, then suppressing continued brute-force attempts and preventing reuse of exposed credentials.

#### ▶ 4.1) Account-Level Containment

- **Force password reset for `webadmin` and any other accounts with verified suspicious attempts** (Finding 4).  
  *Why:* Once a successful login is confirmed (Finding 5), the credential must be treated as compromised, regardless of whether the original compromise was brute force, reuse, or recovery from logs (Finding 8).

- **Invalidate active sessions/tokens for the compromised account** (application session store / auth tokens).  
  *Why:* Password changes alone do not always terminate existing sessions. Session invalidation prevents attackers from retaining access if they already established a session following the successful logins at `10:00:12` and `10:05:20`.

- **Temporarily disable the account if operationally feasible until verification is complete.**  
  *Why:* Disabling reduces risk of continued abuse during investigation (especially given secondary login reuse from a different IP).

#### ▶ 4.2) Traffic-Level Containment

- **Block or rate-limit the primary attacking IP `198.51.100.100` at WAF / reverse proxy / firewall layers.**  
  *Why:* The investigation attributes the bulk of brute-force activity to this IP (Finding 1) and shows sustained automated attempts against multiple usernames.

- **Add temporary blocks for the secondary login IP `198.23.200.101` pending validation.**  
  *Why:* The source change shortly after a successful authentication is a strong post-compromise indicator (Finding 6). Blocking reduces risk of immediate follow-on actions from that infrastructure.

- **Implement emergency rate limiting on `/api/login`.**  
  *Why:* The entire abuse pattern in this incident concentrates on this endpoint (Finding 7). Rate limiting is the fastest mitigation to reduce automated guessing and credential stuffing impact.

Containment actions should be documented alongside the incident timeline in `case-report.md` and linked to detection artifacts in `detection-artifact-report.md` (this lab).

---

### 5) Eradication Actions

This section documents steps taken to remove attacker footholds and eliminate systemic weaknesses that enabled the compromise.

Eradication for authentication abuse incidents is primarily about (1) ensuring compromised credentials can no longer be used and (2) closing design flaws that reduce attacker effort.

#### ▶ 5.1) Credential Hygiene and Rotation

- **Rotate credentials for all targeted high-value accounts** (`webadmin`, `websitemanager`, `ftp`) even if not confirmed compromised.  
  *Why:* Attackers often test multiple accounts and may compromise more than one. The presence of targeted valid accounts (Finding 4) warrants preventative rotation to reduce residual risk.

- **Invalidate password resets across dependent systems** (any services that reuse these credentials).  
  *Why:* Credential reuse expands blast radius beyond the web app.

#### ▶ 5.2) Remove Credential Exposure in Logs (Critical)

- **Eliminate logging of credential-derived values in authentication logs (Finding 8).**  
  *Why:* The investigation confirmed `hashed_password` was not a true hash; it was Base64-encoded and reversible to plaintext `webadmin1234`. This is a direct “unsecured credentials” risk (T1552) and materially reduces attacker effort.

- **Implement secure password handling and storage practices** (one-way hashing + salt; avoid logging secrets).  
  *Why:* Even if rate limiting is strong, logging reversible secrets creates an alternate compromise path for anyone with log access.

#### ▶ 5.3) Reduce Account Enumeration Signal

- **Normalize authentication failure responses** so non-existent user vs incorrect password cannot be distinguished.  
  *Why:* The investigation shows explicit enumeration behavior (Finding 3: 9 non-existent usernames). Reducing response differences increases attacker cost and decreases targeting accuracy.

Eradication actions and rationale should be reflected in the lab’s dedicated `detection-and-hardening-recommendations.md` (standalone deep-dive), with the walkthrough providing a high-level summary under **Detection and Hardening Opportunities**.

---

### 6) Recovery Actions

This section describes how access and business operations were safely restored while reducing probability of repeat abuse.

Recovery actions focused on restoring legitimate access while ensuring newly applied controls (rate limiting, credential policies, monitoring) are operational.

- **Re-enable affected accounts only after password rotation and session invalidation are confirmed.**  
  *Why:* Prevents attackers from reusing existing sessions or recently guessed credentials.

- **Require MFA for privileged accounts (starting with `webadmin`).**  
  *Why:* MFA breaks credential-only compromise paths such as brute force, reuse, and credential recovery from logs.

- **Review application account privileges for least privilege.**  
  *Why:* `webadmin` compromise represents high-risk access. Reducing privilege limits impact if compromise recurs.

---

### 7) Validation and Post-Incident Monitoring

This section documents how remediation effectiveness was verified and what monitoring was applied to detect reattempts.

Validation focused on confirming that the same exploitation chain could not immediately repeat:

1. **No further successful authentications** for `webadmin` from suspicious sources after password reset.
2. **No repeated burst failures** from `198.51.100.100` against `/api/login` following blocks/rate limiting.
3. **No recurrence of secondary source reuse patterns** (Finding 6 behavior pattern) across other accounts.

Monitoring recommendations (implemented as alerts and dashboards) included:

- Spike detection on failed logins to `/api/login`
- New source IP detection for privileged accounts
- Correlation rule: high-volume failures → success within short window → new IP reuse within minutes
- Monitoring for repeated targeting of non-existent usernames (Finding 3 enumeration pattern)

Detection logic and fields are documented in `detection-artifact-report.md`, and hardening improvements are documented in `detection-and-hardening-recommendations.md`.

---

### 8) Communication and Coordination

This section summarizes how response actions were coordinated across security, engineering, and business stakeholders.

Coordination focused on ensuring both security remediation and application functionality were maintained:

- **Security / SOC:** led triage, containment decisions, and correlation development
- **App Engineering:** removed insecure credential logging and deployed authentication hardening changes
- **IT / Identity Owners:** enforced MFA and password policy improvements for privileged accounts
- **Management / Stakeholders:** notified due to confirmed account compromise and risk of sensitive access

This coordination model ensured emergency containment (blocks, resets) was followed by durable eradication (secure logging + authentication redesign).

---

### 9) Lessons Learned

This section captures response insights and defensive gaps identified during incident handling, with direct ties to investigation findings.

Key lessons include:

- **Credential exposure in logs dramatically reduces attacker cost.** The Base64-encoded `hashed_password` field (Finding 8) effectively turned authentication logs into a credential source.
- **Automation fingerprints matter.** Consistent User-Agent and rapid retries supported automation determination early (Finding 2).
- **Endpoint concentration is actionable.** The attacker targeted a single endpoint (`/api/login`, Finding 7), enabling rapid containment via rate limiting and focused monitoring.
- **Secondary login sources are high-signal.** The rapid shift to `198.23.200.101` after the initial compromise (Finding 6) is a strong compromise confirmation indicator.

These lessons informed the long-term control plan documented in `detection-and-hardening-recommendations.md`.

---

### 10) Related Documentation

- `web-application-authentication-abuse-investigation.md` — analyst workflow, log pivots, and validation steps (Findings 1–8)  
- `case-report.md` — reconstructed attacker timeline and business impact framing  
- `MITRE-ATT&CK-mapping.md` — technique classification and behavioral mapping  
- `incident-summary.md` — executive-level overview of incident and response  
- `detection-artifact-report.md` — detection-relevant authentication artifacts and correlation opportunities  
- `detection-and-hardening-recommendations.md` — standalone engineering and hardening plan (detailed)  

