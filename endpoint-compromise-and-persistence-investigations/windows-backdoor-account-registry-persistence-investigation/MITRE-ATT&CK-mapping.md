# MITRE ATT&CK Mapping - Windows Host Compromise Investigation (Backdoor Account Creation and Registry-Based Persistence)

This document maps attacker behaviors observed during this investigation to MITRE ATT&CK tactics and techniques using direct evidence from Windows Security logs, Sysmon/registry telemetry, and PowerShell execution logs.

All mappings are based on confirmed activity reconstructed during analysis rather than inferred attacker intent or assumed tooling.

The purpose of this mapping is to support standardized incident classification, detection coverage validation, and alignment with threat modeling frameworks commonly used by security operations teams.

---

## How This Mapping Was Performed

Techniques were mapped by reviewing:

- Command-line and process creation telemetry identifying account management activity
- Windows Security account management events validating local user creation
- Registry event logs confirming SAM hive modifications tied to the new account
- Process execution logs revealing WMIC-based remote command execution
- PowerShell engine and pipeline logs exposing encoded script execution
- Decoded PowerShell payload revealing outbound web communication

Each technique below references the investigative pivots and artifacts that supported classification.

---

## MITRE ATT&CK Mapping (Narrative View)

### Persistence

#### Create Account: Local Account (T1136.001)

**Observed Behavior**  
A new local user account named `A1berto` was created using built-in Windows account management utilities.

This was first identified through command-line searches for `net user /add`, which revealed repeated execution of:

`net user /add A1berto paw0rd1`

Account creation was then confirmed using Windows Security Event ID `4720`, which explicitly logged creation of the new local user.

**Evidence Sources**  
- Windows Security Event ID `4720` (user account created)  
- Process creation telemetry (`Event ID 4688`) capturing `net.exe` execution  
- CommandLine field containing `/add A1berto paw0rd1`

**Why This Maps to ATT&CK**  
ATT&CK defines this technique as persistence through creation of local accounts to maintain future access. The observed behavior directly matches this definition.



### Defense Evasion

#### Masquerading (T1036)

**Observed Behavior**  
The attacker-created username `A1berto` visually resembled an existing legitimate user account `Alberto`, differing only by substitution of the number “1” for the letter “l”.

This was identified during review of the `User` field distribution across events and comparison with legitimate usernames present in the dataset.

**Evidence Sources**  
- Username field patterns across Windows Security events  
- Presence of both `Alberto` and `A1berto` accounts in telemetry

**Why This Maps to ATT&CK**  
Masquerading includes the use of look-alike names to blend malicious activity with legitimate accounts, reducing the likelihood of visual detection by administrators.



### Lateral Movement / Execution

#### Windows Management Instrumentation (T1047)

**Observed Behavior**  
The backdoor account was created remotely using WMIC, rather than by local interactive logon.

Process creation telemetry revealed execution of:

`C:\Windows\System32\Wbem\WMIC.exe /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"`

This indicates remote process creation against the target workstation using WMI.

**Evidence Sources**  
- Windows Security Event ID `4688` process creation logs  
- CommandLine field containing `WMIC.exe process call create`  
- Target node parameter specifying remote system

**Why This Maps to ATT&CK**  
ATT&CK defines WMI abuse as a technique for executing commands remotely using native Windows management capabilities, which exactly matches the observed behavior.



### Persistence

#### Modify Registry (T1112)

**Observed Behavior**  
Registry artifacts were written under the SAM hive confirming Windows registered the newly created account.

Registry telemetry surfaced the following key:

`HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto`

This was identified using targeted registry searches filtered by hostname and username.

**Evidence Sources**  
- Sysmon/registry Event ID `12` (registry object creation)  
- TargetObject field showing SAM hive path for `A1berto`  
- Host filtering to `Micheal.Beaven` where account was created

**Why This Maps to ATT&CK**  
Modification of registry keys associated with account metadata constitutes persistence via registry modification, aligning with ATT&CK’s Modify Registry technique.



### Execution

#### PowerShell (T1059.001)

**Observed Behavior**  
Encoded PowerShell commands were executed on host `James.browne`, identified through repeated PowerShell engine events.

PowerShell logs contained `-enc` flags and Base64-encoded payloads in the `HostApplication` field, indicating obfuscated command execution.

A total of `79` PowerShell engine events (`Event ID 4103`) were observed for this host.

**Evidence Sources**  
- PowerShell Event ID `4103` (engine activity)  
- HostApplication field containing `-enc` with Base64 content  
- Host attribution: `James.browne`

**Why This Maps to ATT&CK**  
ATT&CK defines PowerShell execution as a common technique for executing attacker-controlled scripts and commands, especially when obfuscation is used.



### Command and Control

#### Application Layer Protocol: Web (T1071.001)

**Observed Behavior**  
Decoded PowerShell payload revealed outbound HTTP communication to:

`http://10.10.10.5/news.php`

The payload was double Base64-encoded and required multi-stage decoding using UTF-16LE decoding to fully reconstruct the destination.

**Evidence Sources**  
- Decoded PowerShell script content  
- Extracted URL: `http://10.10.10.5/news.php`  
- Defanged IOC: `hxxp[://]10[.]10[.]10[.]5/news[.]php`

**Why This Maps to ATT&CK**  
ATT&CK classifies outbound command-and-control over HTTP/S as Application Layer Protocol communication, which matches the recovered web request behavior.

---

## MITRE ATT&CK Mapping (Table View)

| Tactic | Technique ID | Technique Name | Evidence Summary | Evidence Source |
|--------|--------------|----------------|------------------|-----------------|
| Persistence | T1136.001 | Create Account: Local Account | New user `A1berto` created via `net user /add` | Event ID 4720, Event ID 4688 |
| Defense Evasion | T1036 | Masquerading | Username mimicked legitimate user `Alberto` | Username field correlation |
| Lateral Movement / Execution | T1047 | Windows Management Instrumentation | WMIC used for remote account creation | CommandLine in Event ID 4688 |
| Persistence | T1112 | Modify Registry | SAM hive registry keys written for new account | Registry Event ID 12 |
| Execution | T1059.001 | PowerShell | Encoded PowerShell execution on `James.browne` | Event ID 4103 |
| Command and Control | T1071.001 | Application Layer Protocol: Web | Outbound HTTP request to `/news.php` endpoint | Decoded PowerShell payload |

This table provides a condensed reference suitable for reporting, detection validation, and technique tracking across multiple investigations.

---

## Detection and Control Relevance

Mapping behaviors to MITRE ATT&CK supports defensive operations by:

- Highlighting detection opportunities for remote account creation using WMIC  
- Reinforcing monitoring of registry changes under SAM hive paths  
- Supporting alerting for encoded PowerShell execution (`-enc`)  
- Identifying web-based C2 indicators originating from script interpreters  

Detection opportunities and preventive control recommendations associated with these techniques are documented in:

- `detection-artifact-report.md`  
- `detection-and-hardening-recommendations.md`

---

## Notes and Assumptions

- All techniques are mapped based solely on behaviors confirmed in available telemetry.
- No interactive logon by the backdoor account was observed within the dataset timeframe.
- Mapping avoids attribution to specific malware families or threat actors.

This mapping reflects how ATT&CK is commonly applied during host-based intrusion investigations using log-driven reconstruction workflows.
