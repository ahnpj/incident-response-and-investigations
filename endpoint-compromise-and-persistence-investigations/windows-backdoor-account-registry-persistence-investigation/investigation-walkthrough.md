# Windows Host Compromise Investigation (Backdoor Account Creation and Registry-Based Persistence)

---

## Executive Summary
This investigation analyzed a suspected Windows host compromise using Splunk telemetry to determine whether an adversary established persistence through local account creation and registry activity. Evidence showed a backdoor user account was created using built-in Windows utilities, registry artifacts were written under the SAM hive consistent with the new account, and follow-on activity included encoded PowerShell execution that revealed outbound communication to a specific web resource. Security, Sysmon/registry, and PowerShell logs were correlated to reconstruct attacker behavior and document artifacts relevant to detection and response.

---

## Incident Scope
This investigation focused on reconstructing suspicious activity observed in pre-ingested Windows logs within Splunk, treating the dataset as if it were received after an alert on a Windows workstation. Scope included validating whether a backdoor local account was created, identifying associated registry artifacts, evaluating impersonation intent, and tracing related follow-up activity including remote command execution and PowerShell-based outbound communication. Analysis was limited to the available log sources (Security, Sysmon/registry, and PowerShell) contained within the dataset and did not involve direct interaction with the Windows host generating the logs.

---

## Environment, Evidence, and Tools
This investigation was performed in an environment composed of multiple virtual machines supporting log analysis in Splunk. The primary system used for analysis was an AttackBox VM, which served as the main workstation for interacting with the environment, running searches, and accessing the logging interface. The AttackBox was assigned internal IP addresses `10.201.84.11` and `10.201.85.188`. The Splunk server was hosted on a separate VM accessible at `10.201.83.141`, which was used to access the Splunk web interface. A Windows VM operated in the background to generate telemetry and forward Windows event logs into Splunk; direct access to that VM was not required.

Because internal IP addresses in the environment were ephemeral and could change on restart or refresh, active IPs were verified before beginning analysis to ensure connections were made to the correct systems.

<blockquote>
When I first accessed the Splunk interface and ran a basic search against the "main" index, I noticed that event data was already present. This is expected based on how the environment is structured. The Windows VM operating in the background is configured to automatically forward its event logs into Splunk as soon as the environment becomes active. Because of that, the ingestion pipeline is already running by the time I begin my analysis, and the main index contains a baseline of system activity, service events, and any simulated malicious behavior that occurred on the host. This pre-ingested data allowed me to start reviewing events immediately without having to manually trigger log generation or configure forwarding on my own.
</blockquote>

- **Platform:** Splunk Enterprise (web interface)
- **Data Source:** Pre-ingested Windows event logs (Security, Sysmon/registry, and PowerShell logging)
- **Index Used:** `main`
- **Role:** Acting as a SOC analyst / incident responder reviewing logs after a suspected compromise on a Windows endpoint.

---

## Investigative Questions
The following investigative questions guided analysis and defined the pivots used during evidence review. Each question was designed to validate adversary behavior, establish attribution to specific hosts and identities, and identify concrete artifacts relevant to follow-up response and detection development.

- Was a backdoor local user account created, and what username was used?
- How was the backdoor account created (locally vs remotely), and what command was responsible?
- What registry artifacts were written or modified in association with the backdoor account, and what is the relevant registry path?
- Which legitimate user was the adversary attempting to impersonate?
- Was the backdoor account used for authentication attempts, and if so, how many attempts occurred during the captured timeframe?
- Which host executed suspicious PowerShell activity, and how extensive was that activity?
- What outbound destination was contacted by the encoded PowerShell payload, and what is the full URL?

---

## Investigation Timeline
The following timeline summarizes the sequence of notable events and investigative milestones reconstructed from the available log evidence.

- **T0 — Baseline review and dataset sizing:** Event volume in the `main` index was assessed to establish investigation scope and confirm data availability.
- **T1 — Backdoor account creation identified:** Command-line evidence and account management telemetry indicated creation of a new local user consistent with backdoor access.
- **T2 — Registry artifacts correlated:** Registry activity associated with the created username surfaced under SAM hive paths consistent with local account registration.
- **T3 — Impersonation intent observed:** Username patterns suggested the adversary attempted to mimic an existing legitimate account using a visually similar name.
- **T4 — Remote execution method confirmed:** Process creation telemetry revealed the account creation was performed via remote execution using WMIC.
- **T5 — Backdoor usage evaluated:** Authentication telemetry was reviewed to determine whether the backdoor account was used for logon attempts.
- **T6 — Suspicious PowerShell host identified:** PowerShell-related telemetry narrowed suspicious script execution to a single host.
- **T7 — PowerShell activity quantified and decoded:** Engine/pipeline events were counted, the encoded payload was decoded, and the outbound URL was extracted and defanged.

---

## Investigation Walkthrough

### Dataset Familiarization (Event Count in `main`)
The investigation began by establishing the overall dataset size in the `main` index to set expectations for scope and query performance.

```spl
index=main
| stats count

This query returns a single row with a count field, providing the total number of events available for analysis. In addition to confirming that the correct index was being queried and that ingestion was present, the event count provided a quick sense of scale for the investigation.

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-01.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 1</em>
</p>

As an alternative approach, the index could be queried directly using `index=main`, and the event count could then be referenced from the [Events] tab by viewing the count displayed next to the `Events` label.

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-02.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 2</em>
</p>

### Backdoor Account Creation Evidence (Command-Line and Account Management Telemetry)

With dataset scale established, analysis shifted toward identifying whether a new local user account was created. Because adversaries frequently use built-in commands such as `net user` for account creation, searches focused on command-line indicators and process execution telemetry.

A starting point was searching for `net user` activity, including explicit account creation patterns:

```spl
index=main ("net user" OR "net user /add")

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-03.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 3</em>
</p>

**(Step 2-a)**

Reviewing raw events surfaced a suspicious command that added a new local user and included a password, which is highly anomalous outside legitimate provisioning workflows. Across returned results, the command consistently observed was:

`net user /add Alberto paw0rd1`

The same action was recorded by multiple telemetry sources. The activity appeared in `Event ID 1`, `Event ID 4688`, and `Event ID 800`, each capturing process execution through a different logging perspective:

- `Event ID 4688` (Windows Security – Process Creation): Recorded creation of the process and included the full command line responsible for executing net.exe with the /add parameters. The inclusion of the username and password in clear text strongly suggested unauthorized account creation activity.
- `Event ID 1` (Sysmon Process Creation): Captured the same command execution with additional metadata such as parent process context and hash information. Although the hash was not required for this stage, corroboration across sources increased confidence in the finding.
- `Event ID 800` (PowerShell or Script Execution Engine): While not directly representing PowerShell script content, this event showed the system also logged the activity at an engine/script level, further confirming the action was observed through multiple channels.

Process IDs (PIDs) associated with returned events were reviewed. As expected, PIDs differed across logs capturing the same action, but the events consistently pointed back to execution of `net.exe` with the `/add` parameters. Taken together, the `/add` flag, the presence of a cleartext password, and corroboration across multiple telemetry channels—this activity was assessed as adversary-driven creation of a backdoor local account using standard Windows utilities.


**(Step 2-b)**

To validate account creation from an account management perspective, Windows Security events tied to account creation (for example, Event ID 4720) were also queried:

```spl
index=main EventID=4720

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-04.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 4</em>
</p>

Reviewing these events confirmed the creation of a new user account and clarified the username introduced as the backdoor. On one of the infected hosts, the adversary successfully created a backdoor user named `A1berto`.

### Registry Artifact Correlation (Persistence-Related Account Metadata)

After confirming suspicious account creation, analysis pivoted to registry activity to determine whether persistence-related artifacts were present on the system. When new local accounts are introduced during intrusions, registry activity is often a high-signal area because Windows writes account and profile metadata and attackers may tamper with related keys.

Because the created username was known (`A1berto`), the search focused on registry events tied to that name. The analysis prioritized `Registry Event ID 12` (object creation or deletion) because it frequently captures new keys being written. A targeted search was used to surface events tied to the relevant host and username:

```spl
index=main Hostname="Micheal.Beaven" EventID=12 A1berto

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-05.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 5</em>
</p>

<blockquote> 
I filtered by the hostname because the backdoor account was created on that specific machine. Using the hostname kept the registry search focused on the same system involved in the compromise and prevented unrelated registry events from other hosts from cluttering the results. This made it easier to spot the exact registry key tied to the newly created user.
</blockquote>

Within returned registry event details, the relevant path stood out. Windows maintains local user profile metadata under the SAM hive, and events revealed an entry explicitly referencing the backdoor username:

`HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

This registry key confirmed that Windows registered the newly created account, and the timing aligned with the earlier command-line evidence. In these registry events, the `TargetObject` field is the key field because it contains the full registry key or value path that was created, modified, or deleted. Without `TargetObject`, the event would indicate a registry change occurred but would not identify which key was impacted, which is why `TargetObject` was required to extract the persistence-relevant artifact.


### Impersonation Intent (Look-Alike Username Identification)

Once account creation and registry artifacts were established, analysis focused on identifying which legitimate identity the adversary attempted to mimic. Adversaries often select usernames that blend into normal naming patterns to reduce detection.

A broad sweep across logs was performed to examine username patterns:

```spl
index=main

During review of the `User` field patterns in the field sidebar, the legitimate username Alberto stood out. The adversary-created backdoor user A1berto differed by a single character swap, a common masquerading pattern that can deceive analysts during sorting or grouping of events. This observation supported the assessment that the adversary intended to blend in as the legitimate user while performing unauthorized actions.

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-06.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 6</em>
</p>

### Remote Execution Confirmation (WMIC-Based Account Creation)

The next pivot focused on how the backdoor account was created. Process creation telemetry (`Event ID 4688`) was used to identify tooling and command construction indicating remote execution.

Process creation events were filtered using:

```spl
index=main EventID=4688

Within returned events, the `CommandLine` field contained a command that connected the account creation to remote execution. The adversary executed WMIC from a remote host to run `net user /add` against the target machine:

```text
C:\windows\System32\Wbem\WMIC.exe /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"

This confirmed the adversary was operating remotely rather than being physically or interactively logged onto the compromised host. WMIC (Windows Management Instrumentation Command-line) is a built-in Windows utility commonly used for querying system information, starting processes, managing services, or controlling remote systems without requiring RDP or an interactive login. Because it is native to Windows environments, it can blend into legitimate administrative activity and enables remote command execution without additional tooling. This command indicated two key points: the adversary executed actions remotely and abused a legitimate administrative tool to create the backdoor account without relying on external malware.

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-07.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 7</em>
</p>


### Backdoor Account Usage Review (Logon Attempt Validation)

After confirming remote account creation, the investigation evaluated whether the backdoor account was used for authentication attempts during the timeframe captured in the dataset.

Events referencing the backdoor username were searched using:

```spl
index=main A1berto

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-08.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 8</em>
</p>

Events tied to the username were reviewed and the `Category` field was examined to understand what types of activity were associated with that identity. If the account had been used for login activity, indicators would typically appear under categories such as `Logon/Logoff` or `Account Management`. Instead, there were no category indicators consistent with authentication activity.

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-09.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 9</em>
</p>

To validate this conclusion using explicit Windows logon event IDs, the `EventID` field was examined for the presence of `4624` (successful logon) and `4625` (failed logon). Neither event ID appeared for the backdoor username. This absence confirmed what the `Category` field suggested: the account was created successfully but was not used for any actual login attempt during the captured timeframe. This pattern supported the interpretation that the account was staged for future access or retained as a fallback.

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-10.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 10</em>
</p>


### Suspicious PowerShell Origin Identification (Host Attribution)

The investigation then pivoted to PowerShell activity to determine follow-on behavior. Encoded PowerShell is frequently used to download payloads, execute scripts in memory, or conceal command intent, making PowerShell telemetry a high-value source.

PowerShell-related logs were searched using:

```spl
index=main PowerShell

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-11.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 11</em>
</p>

The `Hostname` field was reviewed to identify which system generated the PowerShell telemetry. Only a single hostname consistently appeared in the results: **James.browne**. This indicated the suspicious PowerShell activity originated entirely from that machine.

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-12.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 12</em>
</p>


### Malicious PowerShell Volume Measurement (Event ID 4103)

With the affected host identified, analysis measured the extent of suspicious PowerShell execution. The focus was placed on `Event ID 4103`, which logs PowerShell engine activity.

```spl
index=main EventID=4103

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-13.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 13</em>
</p>

Splunk returned 79 events, all associated with the encoded payload activity. This volume suggested repeated execution or a script that generated multiple engine events while unpacking or processing instructions. Quantifying these events provided context for how visible the activity would be in environments with robust PowerShell logging enabled.


### Encoded PowerShell Decoding and URL Extraction (CyberChef + Defang)

After establishing **James.browne** as the host generating suspicious PowerShell telemetry, analysis focused on determining the outbound destination contacted by the encoded command. PowerShell events were reviewed with attention to pipeline execution details (for example, events in the PowerShell channel such as `EventID 800` that can surface execution parameters and context).

```spl
index=main PowerShell

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-14.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 14</em>
</p>

Within the PowerShell events for **James.browne**, the `HostApplication` field contained a long character sequence immediately following the `-enc` flag. The `-enc` flag is used when PowerShell executes a Base64-encoded command, and the presence of a large encoded blob strongly indicated intentional obfuscation. These events also exposed pipeline context and parameter values, where multiple paths were visible in the Details section, including `/admin/get.php`, `/news.php`, and `/login/process.php`.

To safely interpret the encoded command without executing it on the host, the Base64 string from the -enc portion of the event was copied and decoded using CyberChef.

<blockquote> 
CyberChef is useful here because it lets me quickly decode encoded payloads without running anything on the host itself. Since attackers often hide their real commands inside Base64, this step lets me peel back the obfuscation safely.
</blockquote>

The CyberChef recipe used was “From Base64” followed by “Decode text (UTF-16LE).” PowerShell typically encodes commands in UTF-16LE before Base64 encoding them, so this decoding chain aligns with how encoded PowerShell payloads are constructed. After decoding the first Base64 layer, the output was not yet the final script; embedded within the decoded text was another Base64 block, indicating a second obfuscation layer. Double-encoding increases complexity and hinders quick interpretation.

During decoding, the first Base64 layer surfaced several possible PHP file paths (`/admin/get.php`, `/news.php`, `/login/process.php`). These paths appeared as part of the script’s internal logic and were not yet the final resolved destination. After decoding the second Base64 block, the payload resolved to a specific endpoint: `news.php`, which clarified that the “different php file” references were intermediate options while the second layer revealed the actual selection.

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-15.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 15</em>
</p>

To complete decoding, the second Base64 blob was copied, the input was cleared, and the same recipe was applied again. This produced the fully decoded PowerShell payload and exposed the outbound web request.

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-16.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 16</em>
</p>

Decoding revealed a plain-text destination pointing to `http://10.10.10.5`. The fully reconstructed destination URL was:

`http://10.10.10.5/news.php`

Before documenting the URL, it was defanged to prevent accidental clicks or direct use in documentation. CyberChef’s Defang URL option was used to escape dots and the `http` scheme, resulting in:

`hxxp[://]10[.]10[.]10[.]5/news[.]php`

<p align="left">
  <img src="images/splunk-backdoor-and-registry-investigation-17.png?raw=true&v=2" 
       style="border: 2px solid #444; border-radius: 6px;" 
       width="800"><br>
  <em>Figure 17</em>
</p>


---


## Findings Summary

This section consolidates the high-confidence conclusions derived from correlated Security, Sysmon/registry, and PowerShell telemetry. Findings are limited to what can be supported directly by the available evidence within scope.

- A new local user account was created on one of the Windows hosts, acting as a backdoor account.
- Registry keys tied to local accounts were modified to reflect the presence of this backdoor user, indicating that the attacker was making persistent changes on the host.
- Logs showed that the attacker was attempting to impersonate a legitimate user, which helped explain the choice of username and the behavioral pattern around logon events.
- The backdoor account was created remotely using a WMIC command that executed net user /add on the target host. This demonstrates the use of “living off the land” binaries for remote administration and lateral movement.
- Login attempts from the backdoor user were identifiable in the Security logs, making it possible to count and describe how often the attacker tried to authenticate with that account.
- One host clearly stood out as the infected endpoint based on its suspicious PowerShell history.
- PowerShell logging, which is sometimes disabled in real environments, proved extremely valuable here. It allowed me to count the number of malicious PowerShell events and reconstruct the encoded command.
- Decoding the PowerShell payload exposed a full URL contacted by the script, which would be critical for further threat intelligence (for example, blocking the domain/IP, checking reputation, or pivoting in other tools).

Overall, the logs painted a classic small-scale intrusion story: account creation, registry modification, impersonation attempts, remote administration abuse, and a scripted outbound web request.

**Detailed Evidence Reference:**  
For a full, artifact-level breakdown of logs, alerts, and forensic indicators that support these findings — including where each artifact was identified during the investigation — see: **`detection-artifact-report.md`**

---

## Defensive Takeaways

This section summarizes key defender-relevant patterns observed during the investigation, focusing on operational lessons and recognizable behaviors rather than specific remediation steps.

- Event volume context matters. Starting with a simple `stats count` over the index gave me a quick sense of scale and reassured me that my searches were running over the correct dataset.
- Backdoor accounts leave multiple traces. Between Security events, command-line logs, and registry entries, a single malicious user account shows up in several places. Knowing how to pivot between them is key.
- Registry artifacts are powerful for persistence analysis. Even when you don’t know exactly what to look for at first, combining keyword searches with registry fields makes it possible to spot suspicious changes tied to user accounts.
- Impersonation is often visible in logon patterns. By correlating logon events with the surrounding activity window, it becomes much easier to tell which legitimate user the attacker was trying to mimic.
- Remote execution stands out when you look at WMIC and similar tools. Searching for utilities like `wmic`, `psexec`, or `sc` can quickly surface commands that attackers use for lateral movement and remote changes.
- PowerShell logging is invaluable. When it’s enabled, it turns what would otherwise be opaque encoded commands into something you can fully reconstruct. This reinforced how important it is to enable and retain detailed PowerShell logs in real environments.
- Decoding payloads is worth the extra step. Taking the time to decode the PowerShell payload wasn’t just a neat trick; it gave the exact URL being contacted, which is critical for incident response, threat hunting, and building detections.

This investigation reinforced that Splunk analysis is not only about writing searches; it is about building a coherent narrative that explains what the adversary did, how the actions were performed, and which artifacts matter most for detection and future hunts.

---

## Artifacts Identified

This section lists concrete artifacts uncovered during the investigation that support the final determination and can be used for validation, hunting, detection development, or follow-up analysis.

- Index analyzed: main
- Suspicious account creation command: `net user /add Alberto paw0rd1`
- Backdoor user account confirmed: `A1berto`
- Legitimate user targeted for masquerading: `Alberto`
- Registry key associated with the backdoor account: `HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`
- Remote execution command used to create the backdoor account: `C:\windows\System32\Wbem\WMIC.exe /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"`
- Host used for registry correlation filtering: `Micheal.Beaven`
- Host executing suspicious PowerShell: `James.browne`
- PowerShell engine event volume: `79` events (Event ID `4103`)
- Encoded PowerShell indicator: `-enc with Base64 content in HostApplication`
- PHP paths observed during decoding: `/admin/get.php, /news.php, /login/process.php`
- Outbound destination extracted (raw): `http://10.10.10.5/news.php`
- Outbound destination extracted (defanged): `hxxp[://]10[.]10[.]10[.]5/news[.]php`

**Detailed Evidence Reference:**  
For a full, artifact-level breakdown of logs, alerts, and forensic indicators that support these findings — including where each artifact was identified during the investigation — see: **`detection-artifact-report.md`**

---

## Detection and Hardening Opportunities

This section summarizes high-level detection and hardening opportunities observed during the investigation. For detailed, actionable recommendations — including specific logging gaps, detection logic ideas, and configuration improvements — see: **`detection-and-hardening-recommendations.md`**

### Containment Actions (Recommended)
These actions focus on removing attacker-established persistence and limiting further access.

- Immediately disable and remove the backdoor local account (`A1berto`).
- Reset credentials for impersonated or targeted legitimate accounts.
- Isolate affected hosts (`Micheal.Beaven`, `James.browne`) pending further review.
- Block outbound communication to the identified command-and-control endpoint.
- Preserve relevant logs and registry artifacts for incident documentation.

### Eradication & Hardening Recommendations
These steps reduce exposure to similar persistence techniques.

- Restrict use of account management utilities such as `net user` to approved administrative contexts.
- Monitor and restrict remote execution mechanisms such as WMIC.
- Harden registry auditing for SAM hive paths associated with local account creation.
- Enable and retain PowerShell logging (engine, pipeline, and script block logging).
- Enforce stronger identity validation to prevent look-alike account creation.

### Detection & Monitoring Recommendations
These detections focus on persistence and follow-on execution.

- Alert on local account creation events (`Event ID 4720`) initiated via command-line utilities.
- Detect registry modifications under `HKLM\SAM\SAM\Domains\Account\Users\Names\*`.
- Alert on WMIC-based remote process creation.
- Monitor for encoded PowerShell execution (`-enc`) and multi-layer obfuscation.
- Correlate account creation with outbound network activity and PowerShell execution.

### Response Validation & Follow-Up (Optional)
- Re-review account management and registry modification logs to confirm no additional backdoor accounts or persistence artifacts are introduced.
- Validate that the backdoor account remains disabled or removed and does not reappear.
- Monitor for renewed WMIC-based remote execution attempts or encoded PowerShell activity.
- Confirm that new detections for local account creation and SAM hive modifications would have surfaced the observed behavior.
- Conduct targeted review of authentication logs to ensure no delayed use of the previously created backdoor account.


---

## MITRE ATT&CK Mapping

The following mappings connect observed behaviors to MITRE ATT&CK techniques and cite the specific evidence identified during Security event, registry, and PowerShell log analysis. Mappings are based on directly observed activity and artifacts within scope.

- **Persistence — Create Account (Local Account) (T1136.001):**  
  A new local user account (`A1berto`) was created via command-line execution, confirmed through account management telemetry and process creation logs.

- **Defense Evasion — Masquerading (T1036):**  
  The backdoor account name closely resembled a legitimate user (`Alberto`), indicating intent to blend into normal account activity.

- **Execution / Lateral Movement — Windows Management Instrumentation (T1047):**  
  Remote execution using WMIC was used to create the backdoor account, observed in process creation telemetry containing `WMIC.exe process call create`.

- **Persistence — Modify Registry (T1112):**  
  Registry artifacts under the SAM hive confirmed registration of the new local account, observed via registry event telemetry.

- **Execution — PowerShell (T1059.001):**  
  Encoded PowerShell commands were executed, identified by `-enc` usage and Base64 content in PowerShell logs.

- **Command and Control — Application Layer Protocol: Web (T1071.001):**  
  Outbound communication to an external web endpoint was identified after decoding the PowerShell payload.

### MITRE ATT&CK Mapping (Table View)

| Tactic | Technique | Description |
|------|-----------|-------------|
| Persistence | **Create Account: Local Account (T1136.001)** | A backdoor local account was created via command-line utilities. |
| Defense Evasion | **Masquerading (T1036)** | Look-alike account naming was used to blend with legitimate users. |
| Execution / Lateral Movement | **Windows Management Instrumentation (T1047)** | WMIC was abused for remote execution of account creation commands. |
| Persistence | **Modify Registry (T1112)** | Registry artifacts confirmed local account persistence under the SAM hive. |
| Execution | **PowerShell (T1059.001)** | Encoded PowerShell execution was used to run attacker-controlled logic. |
| Command and Control | **Application Layer Protocol: Web (T1071.001)** | Outbound web communication confirmed attacker command-and-control. |

**Note:** This section provides a high-level summary of observed ATT&CK tactics and techniques. For evidence-backed mappings tied to specific artifacts, timestamps, and investigation steps, see: **`mitre-attack-mapping.md`**

---