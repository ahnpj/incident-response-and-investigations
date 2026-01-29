# Detection Artifact Report — Windows Malware Intrusion Lifecycle Investigation (Lateral Movement and Multi-Stage Host Compromise on Windows)

### 1) Purpose and Scope
This report documents the **network, authentication, and host-based artifacts** observed during the Windows Host Malware Intrusion Lifecycle investigation. The goal is to provide a **standalone, detection-engineering-focused** reference that a SOC can use to build alerts, hunting queries, and correlation logic based on the *confirmed* attacker behaviors in this lab.

All artifacts below are derived from evidence and pivots documented in:
- `windows-host-malware-instrusion-lifecycle-investigation.md` (step-by-step pivots, screenshots, and validation workflow)
- `case-report.md` (reconstructed attacker timeline and confirmed impact)
- `MITRE-ATT&CK-mapping.md` (technique classification)

Where possible, artifacts include **timestamps, event IDs, file names, paths, and behavioral context** to support operational detection.

---

### 2) Environment and Log Sources
This section summarizes the telemetry sources used to identify the artifacts listed in this report.

#### ▶ 2.1) Primary sources referenced throughout the investigation
- **Firewall telemetry** — inbound scan/probe patterns, service targeting, and source/destination relationships
- **OpenSSH/Operational logs** — authentication failures and successful login confirmation (noting variable client source ports)
- **Windows Security Event Log** — local account creation, privileged group membership changes, and account deletions
- **Sysmon (Microsoft Sysinternals)** — process creation, file creation events, and registry value modifications

#### ▶ 2.2) Host and Entities (confirmed)
- **Attacker source:** `192.168.1.33`
- **Victim host:** `192.168.1.43`
- **Services targeted:** SSH (`22`), RDP (`3389`)

---

### 3) High-Confidence Attack Sequence Anchors
This section lists the **confirmed anchor events** that the rest of the detection artifacts correlate to. These anchors should be used to build timelines and multi-signal detections.

| Anchor | What it Represents | Evidence Source | Key Details |
|---|---|---|---|
| External scan activity | Pre-auth recon/service probing | Firewall logs | Source `192.168.1.33` targeting `192.168.1.43` on `22`/`3389` |
| Brute-force attempts | Repeated failed SSH auth attempts | OpenSSH/Operational | Failures followed by success from same source |
| First confirmed unauthorized access | First successful SSH login | OpenSSH/Operational | `11/18/2022 5:14:08 PM` (administrator login) |
| Archive extraction | Malware tooling staged via extraction | Sysmon Event ID `1` (ProcessCreate) | `C:\Program Files\7-Zip\7z.exe` → `7z e keylogger.rar` at `11/18/2022 5:22:40 PM` |
| Malware file creation | Dropped payload artifacts | Sysmon Event ID `11` (FileCreate) | `rundll33.exe` at `5:22:46 PM`, `svchost.exe` at `5:22:50 PM` |
| Persistence creation | Registry autorun established | Sysmon Event ID `13` (RegistryValueSet) | `Windows Atapi x86_64 Driver` at `5:24:21 PM`, `Windows SCR Manager` at `5:25:43 PM` |
| Persistence account created | New local user | Security Event ID `4720` | New account: `sysadmin` (created immediately after successful auth) |
| Admin privileges granted | Local Administrators modified | Security Event ID `4732` | `sysadmin` added to Administrators |
| Cleanup / impact action | Account deletion | Security Event ID `4726` | Deleted account: `DRB` (post-access activity) |

---

### 4) Network Reconnaissance and Service Targeting Artifacts
This section documents **pre-authentication** indicators showing the attacker was actively identifying and testing exposed services.

#### ▶ 4.1) Artifact: Repeated inbound connection attempts from a single source
**Observed behavior:** Firewall telemetry shows repeated inbound activity from `192.168.1.33` targeting `192.168.1.43`, consistent with scanning/probing.

**Why this matters:** Recon is an early-stage signal that often precedes brute force and exploitation attempts. In this lab, recon preceded the SSH brute-force sequence.

**Fields to capture / normalize (recommended):**
- `src_ip`, `dest_ip`
- `dest_port` (notably `22`, `3389`)
- `action` (allow/deny)
- `count` over a window (e.g., 5–15 minutes)

**Detection guidance:**
- Alert when a single external IP targets **multiple ports** on the same internal host (service discovery).
- Escalate severity when a recon pattern is followed by authentication failures on the same service.

#### ▶ 4.2) Artifact: RDP service exposure probe (port 3389)
**Observed behavior:** Port `3389` was included in targeted service activity (alongside SSH).

**Why this matters:** Even if compromise occurred through SSH, concurrent probing of RDP indicates the attacker was exploring additional access paths.

**Detection guidance:**
- Detect repeated `3389` connection attempts from a single source.
- Correlate with `22` activity to identify multi-service probing against the same host.

---

### 5) SSH Brute Force and Successful Authentication Artifacts
This section documents **credential access / initial access** indicators in OpenSSH telemetry.

#### ▶ 5.1) Artifact: High-frequency SSH authentication failures (brute force)
**Observed behavior:** OpenSSH logs recorded repeated authentication failures from `192.168.1.33` prior to success.

**Why this matters:** This is a high-confidence brute force signature. The investigation explicitly mapped this to **MITRE Brute Force (T1110)** based on repeated failures followed by success.

**Operational note from the investigation:** The OpenSSH logs show varying `port XXXXX` values, which represent changing **client source ports** and do not invalidate correlation by IP/time.

**Detection guidance:**
- Alert when failures exceed threshold (example): `>= 10 failures in 5 minutes` for the same `src_ip` + `dest_host`.
- Escalate to critical when a **successful login** occurs from the same `src_ip` after a failure burst.

#### ▶ 5.2) Artifact: First confirmed unauthorized successful SSH login (administrator)
**Observed artifact (time anchor):**
- First successful login to the `administrator` account occurred at: **`11/18/2022 5:14:08 PM`**

**Why this matters:** This timestamp is the pivot point for host-level scoping. In the investigation walkthrough, this time was used to narrow the Sysmon hunting window for file creation and persistence changes.

**Detection guidance:**
- Alert on successful SSH login to privileged/local admin accounts.
- Increase severity if preceded by brute-force failures from the same IP.

---

### 6) Windows Security Log — Identity and Privilege Manipulation Artifacts
This section documents account-level persistence and privilege escalation artifacts captured in Windows Security events.

#### ▶ 6.1) Artifact: Attacker-created local user account (`sysadmin`)
**Observed artifact:**
- **Security Event ID:** `4720` (user account created)
- **New account identified:** `sysadmin`
- **Correlation:** Identified as the only account creation event occurring after confirmed unauthorized SSH login (per walkthrough analysis).

**Why this matters:** Creating a new local account after initial access is a classic persistence method and reduces dependence on the initially compromised credentials.

**Detection guidance:**
- High-severity alert when `4720` occurs on a workstation/server outside provisioning workflows.
- Correlate with:
  - recent successful remote logon events
  - known brute-force patterns
  - process creation anomalies in the surrounding window

#### ▶ 6.2) Artifact: Privilege escalation — `sysadmin` added to Administrators
**Observed artifact:**
- **Security Event ID:** `4732` (member added to a security-enabled local group)
- **Group:** Administrators (local)
- **Correlation:** Identified after `sysadmin` creation to confirm attacker granted privileged access.

**Why this matters:** This converts access into full host control and can enable security tooling tampering, lateral movement, and long-term persistence.

**Detection guidance:**
- Trigger a critical alert when `4732` targets Administrators and is correlated to a newly created account.
- Add enrichment:
  - who performed the change (Subject)
  - target member (MemberName)
  - time delta from account creation

#### ▶ 6.3) Artifact: Account deletion (cleanup or access disruption) — `DRB`
**Observed artifact:**
- **Security Event ID:** `4726` (user account deleted)
- **Deleted account:** `DRB`
- **Context from walkthrough:** Deletion occurred after attacker created and elevated their persistence account, consistent with cleanup or impact behavior.

**Why this matters:** Deleting accounts can be used to reduce forensic visibility, remove legitimate access, or confuse responders. This aligns with defense evasion/impact behavior noted in the lab.

**Detection guidance:**
- Alert on `4726` events outside normal admin change windows.
- Correlate with attacker persistence establishment (e.g., `4720`/`4732`) and other compromise indicators.

---

### 7) Sysmon — Process Execution Artifacts
This section documents process execution artifacts used to validate malware deployment mechanics.

#### ▶ 7.1) Artifact: Archive extraction using 7-Zip (payload staging)
**Observed artifact (confirmed):**
- **Sysmon Event ID:** `1` (ProcessCreate)
- **Process image:** `C:\Program Files\7-Zip\7z.exe`
- **Command line:** `7z e keylogger.rar`
- **Timestamp:** **`11/18/2022 5:22:40 PM`**

**Why this matters:** This is the key staging event that bridges initial access to malware deployment. The extraction command was used as the pivot to identify created payload files via Sysmon FileCreate events immediately after.

**Detection guidance:**
- Alert when archival utilities (7z/winrar) extract archives in proximity to remote logons.
- Increase severity when extraction is followed by creation of `.exe` files in user-writable directories.

**Hunting pivot (as used in the lab):**
- Use the extraction timestamp (`5:22:40 PM`) as the center of the window to search for:
  - Sysmon `11` file creation events
  - Sysmon `13` registry modifications
  - Security `4720/4732` identity events

---

### 8) Sysmon — File Creation Artifacts (Dropped Malware)
This section documents payload files created as a direct result of archive extraction.

#### ▶ 8.1) Artifact: Executables created by `7z.exe` immediately after extraction
**Observed artifacts (confirmed):**
- **Sysmon Event ID:** `11` (FileCreate)
- **Created file 1:** `rundll33.exe` — **`11/18/2022 5:22:46 PM`**
- **Created file 2:** `svchost.exe` — **`11/18/2022 5:22:50 PM`**
- **Attribution:** Both created by `7z.exe` (per investigation walkthrough correlation).

**Why this matters:** The tight time adjacency to the extraction process is a strong indicator these binaries were delivered via the malicious archive rather than normal software activity.

**Known on-disk locations (confirmed later during persistence validation):**
- `C:\Users\Administrator\AppData\Roaming\WPDNSE\rundll33.exe`
- `C:\Users\Administrator\AppData\Roaming\WPDNSE\svchost.exe`

**Behavioral significance:**
- The folder name `WPDNSE` is non-standard and consistent with a malware staging directory.
- Filenames mimic legitimate Windows components (`svchost.exe`, `rundll32.exe` lookalike), supporting masquerading/defense evasion.

**Detection guidance:**
- Alert on `.exe` creation under `AppData\Roaming` (especially unusual/new folders).
- Alert on lookalike binary names in user profile paths.
- Correlate file creation with:
  - prior archive extraction events
  - prior successful remote login events

---

### 9) Sysmon — Registry Persistence Artifacts (Run Key Value Creation)
This section documents persistence established through registry value creation under the Windows **Run key**.

#### ▶ 9.1) Artifact: Registry value created for persistence — “Windows Atapi x86_64 Driver”
**Observed artifact (confirmed):**
- **Sysmon Event ID:** `13` (RegistryValueSet / value modification)
- **Timestamp:** **`11/18/2022 5:24:21 PM`**
- **Registry value name:** `Windows Atapi x86_64 Driver`
- **Associated executable:** `svchost.exe`
- **Executable path:** `C:\Users\Administrator\AppData\Roaming\WPDNSE\svchost.exe`

**Why this matters:** The value name masquerades as legitimate Windows driver terminology, but points to an executable in a user profile staging directory. The timeline also aligns tightly with the file creation window (`5:22:46–5:22:50 PM`).

**Detection guidance:**
- Alert on Run-key value creation when value data points to user profile paths (AppData/Roaming).
- Raise severity when:
  - the value name resembles a Windows component (masquerading)
  - the target executable was newly created minutes earlier

#### ▶ 9.2) Artifact: Registry value created for persistence — “Windows SCR Manager”
**Observed artifact (confirmed):**
- **Sysmon Event ID:** `13`
- **Timestamp:** **`11/18/2022 5:25:43 PM`**
- **Registry value name:** `Windows SCR Manager`
- **Associated executable:** `rundll33.exe`
- **Executable path:** `C:\Users\Administrator\AppData\Roaming\WPDNSE\rundll33.exe`

**Why this matters:** This establishes layered persistence (multiple values created within the same activity window), increasing attacker resilience if one value is removed.

**Detection guidance:**
- Alert when multiple registry autorun values are created within minutes.
- Correlate back to:
  - archive extraction process (`7z.exe`)
  - malware file creation (Sysmon `11`)
  - identity manipulation (Security `4720/4732`)

---

### 10) Cross-Source Correlation Patterns (How to Detect This as a SOC)
This section provides correlation blueprints that mirror the investigation pivots and are resilient to filename changes.

#### ▶ 10.1) Correlation 1: Recon → Brute Force → Successful Auth (same source)
**Signals (confirmed in lab):**
- Firewall recon/probing from `192.168.1.33`
- OpenSSH auth failures from same IP
- OpenSSH success from same IP (administrator) at `5:14:08 PM`

**High-confidence detection logic:**
- If `scan/probe` + `auth_fail_burst` + `auth_success` occur from the same IP within 30–60 minutes → escalate to critical.

#### ▶ 10.2) Correlation 2: Successful Auth → Archive Extraction → Dropped EXEs
**Signals (confirmed in lab):**
- Successful SSH login (administrator)
- `7z.exe` extraction `7z e keylogger.rar` at `5:22:40 PM`
- Sysmon FileCreate of `rundll33.exe` / `svchost.exe` at `5:22:46` / `5:22:50 PM`

**High-confidence detection logic:**
- If a remote login is followed by archive extraction and `.exe` file creation in user profile paths within minutes → treat as malware staging.

#### ▶ 10.3) Correlation 3: Dropped EXEs → Run-key persistence (Sysmon 13)
**Signals (confirmed in lab):**
- New binaries in `...\AppData\Roaming\WPDNSE\`
- Run-key values created at `5:24:21 PM` and `5:25:43 PM` pointing to those binaries

**High-confidence detection logic:**
- Newly created executable + Run-key value pointing to that executable within 2–10 minutes → persistence established.

#### ▶ 10.4) Correlation 4: Account creation + Admin elevation (persistence identity)
**Signals (confirmed in lab):**
- Security `4720` created account `sysadmin`
- Security `4732` added `sysadmin` to Administrators

**High-confidence detection logic:**
- `4720` followed by `4732` affecting Administrators within short window → privileged persistence account creation.

---

### 11) Notes on Indicator Reliability
This section documents which indicators are stable and which are attacker-changeable.

**Highly changeable (do not rely on alone):**
- File names (`svchost.exe`, `rundll33.exe`, archive name `keylogger.rar`)
- Folder names (`WPDNSE`)
- Registry value names (`Windows Atapi x86_64 Driver`, `Windows SCR Manager`)

**More reliable signals (prefer in detection logic):**
- Sequence correlation (remote auth → staging/extraction → dropped EXEs → persistence)
- Event IDs and behavior types (Sysmon `1/11/13`, Security `4720/4732/4726`)
- Persistence targeting user-profile execution paths
- Multiple persistence values created in the same activity window

---

### 12) Closing Summary
This investigation produced a clear, multi-stage detection blueprint for a full host compromise lifecycle:

- External recon and service probing against `192.168.1.43`
- Brute-force SSH attempts from `192.168.1.33` → successful administrator login at `11/18/2022 5:14:08 PM`
- Post-auth tooling staging via `7z.exe` extracting `keylogger.rar` at `5:22:40 PM`
- Dropped malware executables created minutes later (`5:22:46 PM`, `5:22:50 PM`) and stored under `...\Roaming\WPDNSE\`
- Registry autorun persistence established via Sysmon Event ID `13` at `5:24:21 PM` and `5:25:43 PM`
- Identity persistence via local account creation (`sysadmin`) and privileged group modification
- Cleanup/impact behavior via deletion of `DRB`


To detect similar intrusions reliably, prioritize **cross-source correlation** and short-window sequencing rather than static names. This is the same approach used in the investigation walkthrough to confirm compromise and reconstruct the intrusion lifecycle.
