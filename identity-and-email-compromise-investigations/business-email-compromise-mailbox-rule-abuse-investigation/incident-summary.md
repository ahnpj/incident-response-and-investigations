# Incident Summary — Business Email Compromise (BEC) Investigation (Malicious Mailbox Rule Abuse and Account Compromise)

### Overview

This incident involved unauthorized access to an executive Microsoft 365 mailbox, which was subsequently used to approve fraudulent pension withdrawals. The attacker abused legitimate business approval workflows and concealed financial correspondence through malicious inbox rules, delaying detection of the fraud.

The incident was identified after suspicious financial transactions were observed, prompting investigation into potential identity and email compromise rather than endpoint malware activity.

This summary is intended for non-technical stakeholders and focuses on business impact and response rather than technical investigation details.

---

### What Happened

This section summarizes the confirmed sequence of attacker activity at a high level. It focuses on *what occurred* and *how business processes were affected*, rather than the detailed technical steps taken by analysts during investigation.

The following activity was confirmed during the investigation:

- An external actor impersonated a legitimate pension services provider to initiate financial correspondence with the organization.
- Stolen credentials were used to authenticate to an executive mailbox with authority to approve pension withdrawals.
- The attacker created inbox rules that filtered messages containing financial keywords such as `withdrawal`.
- Financial confirmation and approval emails were moved into a hidden folder (`History`) or deleted before reaching the inbox.
- Fraudulent pension withdrawal transactions were approved using the compromised mailbox.

---

### Timeline References

To avoid duplicating timelines across reports, this case package separates timelines by purpose:

- **Business and attack progression timeline**  
  Documented in: `case-report.md` → *Investigation Timeline*  
  This timeline reconstructs the sequence of attacker actions and resulting business impact (authentication, mailbox manipulation, financial approvals).

- **Analyst investigation workflow timeline**  
  Documented in: `investigation-walkthrough.md`  
  This timeline documents how the analyst identified evidence, which tools were used, and how investigative pivots were chosen during analysis.

This distinction reflects real-world SOC documentation practices, where incident chronology and analyst workflow are documented separately.

---

### Impact

This section summarizes the confirmed and potential effects of the incident on business operations and risk exposure, based on evidence reviewed during investigation.

- **Business Impact:** Unauthorized pension withdrawal transactions created financial loss risk and required interruption of financial approval workflows.
- **Systems Affected:** Microsoft 365 executive mailbox and associated financial approval email processes.
- **Operational Disruption:** Finance and leadership teams were required to pause approvals and validate transaction legitimacy.
- **Reputational and Compliance Risk:** Exposure to regulatory and trust-related concerns due to financial process compromise.

No evidence of malware execution, endpoint compromise, or data exfiltration was identified. All observed attacker activity occurred within cloud identity and email services.

---

### Impact Documentation References

Additional technical and operational detail related to impact is documented in:

- `case-report.md` → *Incident Background* and *Evidence Summary*  
  (describes how mailbox abuse enabled fraudulent approvals and how financial routing was identified)

- `investigation-walkthrough.md` → *Financial Impact: Identifying the Destination Bank*  
  (documents how email artifacts were used to identify the receiving financial institution)

These supporting documents contain the technical and evidentiary basis for the impact summarized here.

---

### How It Was Contained

This section summarizes the response actions required to stop ongoing abuse and stabilize affected systems and business processes.

The following actions were required to contain the incident:

- Credentials for the compromised executive account were reset and active sessions invalidated.
- All malicious inbox rules and attacker-used mailbox folders were removed.
- Financial approval workflows were temporarily suspended pending validation.
- Identity and mailbox audit logs were reviewed to confirm no additional accounts were affected.

These actions ensured that the attacker could no longer authenticate, manipulate mailbox configuration, or suppress financial communications.

---

### Response Documentation References

Detailed response procedures and remediation steps are documented in:

- `incident-response-report.md`  
  (documents containment, eradication, recovery, and monitoring actions)

This summary reflects the high-level response outcomes rather than operational step-by-step procedures.

---

### Next Steps

This section summarizes recommended follow-up actions aimed at preventing recurrence and improving detection coverage based on attacker behavior observed during the incident.

Recommended focus areas include:

- Strengthening identity protection for executive and finance users.
- Improving monitoring for mailbox configuration abuse.
- Enhancing financial approval workflows to reduce reliance on email-based authorization.

---

### Prevention and Detection References

Recommendations are intentionally documented across two levels:

- **High-level detection and control opportunities**  
  Documented in: `investigation-walkthrough.md` → *Detection and Hardening Opportunities*  
  This section highlights what types of security gaps were exploited and where detection opportunities exist.

- **Detailed preventive and monitoring controls**  
  Documented in: `detection-and-hardening-recommendations.md`  
  This report provides specific identity, mailbox, logging, and business process control recommendations suitable for implementation by security and IT teams.

This separation mirrors how post-incident improvement actions are typically tracked between investigative findings and engineering remediation plans.


