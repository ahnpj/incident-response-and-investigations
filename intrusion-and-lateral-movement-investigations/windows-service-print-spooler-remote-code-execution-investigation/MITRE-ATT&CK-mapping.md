# MITRE ATT&CK Mapping - Windows Service Exploitation Investigation (Print Spooler Remote Code Execution)

This document maps attacker behaviors observed during this investigation to MITRE ATT&CK tactics and techniques using direct evidence from Windows Security logs, Sysmon telemetry, and network packet capture data.

All mappings are based on confirmed activity reconstructed during analysis rather than inferred attacker intent or assumed tooling.

The purpose of this mapping is to support standardized incident classification, detection coverage validation, and alignment with threat modeling frameworks commonly used by security operations teams.

---

## How This Mapping Was Performed

Techniques were mapped by reviewing:

- Windows Security events related to SMB service interaction and file access
- Sysmon process, file creation, and network connection telemetry
- File system artifacts related to Print Spooler driver staging
- Packet capture data validating reverse shell behavior

Each technique below references the specific investigative artifacts that supported classification.

---

## MITRE ATT&CK Mapping (Narrative View)

### Initial Access

#### Ingress Tool Transfer (T1105)

**Observed Behavior**  
Malicious files were transferred to the target host over SMB as part of Print Spooler service interaction.

Security Event ID `5145` (Detailed File Share) recorded access to the `spoolss` named pipe over the `IPC$` share from attacker-controlled IP `10.0.2.5`, indicating remote interaction with the Print Spooler service interface. Shortly afterward, Sysmon Event ID `11` recorded creation of `printevil.dll` within the Print Spooler driver staging directory.

**Evidence Sources**  
- Security Event ID `5145` with:
  - `RelativeTargetName = spoolss`
  - `ShareName = \\*\IPC$`
  - `IpAddress = 10.0.2.5`
- Sysmon Event ID `11` showing:
  - File created: `C:\Windows\System32\spool\drivers\x64\3\New\printevil.dll`
  - Creating process: `spoolsv.exe`

**Why This Maps to ATT&CK**  
ATT&CK defines Ingress Tool Transfer as delivery of attacker-controlled tools or payloads to a compromised system. The malicious DLL was transferred via SMB through abuse of printer driver distribution mechanisms, matching this technique.



### Execution

#### Service Execution (T1569.002)

**Observed Behavior**  
Attacker-controlled code was executed through the trusted Windows Print Spooler service.

Process telemetry showed that the malicious DLL was loaded and executed by `spoolsv.exe`, followed by execution of `rundll32.exe` as part of the exploitation chain. The timing of execution closely followed DLL staging within the driver directory.

**Evidence Sources**  
- Sysmon process creation logs:
  - Parent process: `spoolsv.exe`
  - Child execution: `rundll32.exe`
- File placement preceding execution:
  - `printevil.dll` written to Print Spooler driver path

**Why This Maps to ATT&CK**  
ATT&CK defines Service Execution as abusing services to run attacker code. The Print Spooler service was directly leveraged to execute attacker-supplied DLLs without user interaction, aligning precisely with this technique.



### Defense Evasion

#### Masquerading (T1036)

**Observed Behavior**  
The malicious payload was disguised as a printer-related DLL and placed into trusted system directories normally used for legitimate driver files.

The filename `printevil.dll` appeared alongside legitimate files such as `unidrv.dll` and `winhttp.dll` during driver staging, making the payload visually blend into normal Print Spooler activity.

**Evidence Sources**  
- Sysmon Event ID `11`:
  - File path: `C:\Windows\System32\spool\drivers\x64\3\New\printevil.dll`
- Presence of legitimate driver files in same directory:
  - `unidrv.dll`
  - `winhttp.dll`

**Why This Maps to ATT&CK**  
Masquerading includes disguising malicious artifacts as legitimate system components and placing them in trusted directories to evade detection, which matches the observed payload staging strategy.



### Command and Control

#### Application Layer Protocol: Web (T1071.001)

**Observed Behavior**  
After payload execution, the compromised host initiated outbound TCP communication to attacker-controlled infrastructure, consistent with reverse shell behavior over web ports.

Sysmon Event ID `3` recorded outbound connections initiated by `rundll32.exe` running as `NT AUTHORITY\SYSTEM` to destination `10.0.2.5` on port `443`. Packet capture analysis confirmed an interactive command session over this connection, including execution of post-exploitation commands.

**Evidence Sources**  
- Sysmon Event ID `3`:
  - Process: `rundll32.exe`
  - User: `SYSTEM`
  - Destination: `10.0.2.5:443`
- Wireshark packet capture:
  - Followed TCP stream showing interactive shell
  - Observed execution of `whoami`

**Why This Maps to ATT&CK**  
ATT&CK classifies outbound command-and-control using HTTP/HTTPS-style ports under Application Layer Protocol: Web. The reverse shell leveraged outbound web ports to bypass inbound firewall controls.



### Discovery

#### System Owner/User Discovery (T1033)

**Observed Behavior**  
Following establishment of the reverse shell, the attacker executed the `whoami` command to validate privilege level and execution context.

Network traffic confirmed command execution and response indicating `NT AUTHORITY\SYSTEM`, verifying full system-level compromise.

**Evidence Sources**  
- Packet capture showing:
  - Command: `whoami`
  - Response: `NT AUTHORITY\SYSTEM`

**Why This Maps to ATT&CK**  
ATT&CK defines System Owner/User Discovery as querying the current user or privilege context after access is obtained, commonly performed during post-exploitation.

---

## MITRE ATT&CK Mapping (Table View)

| Tactic | Technique ID | Technique Name | Evidence Summary | Evidence Source |
|--------|--------------|----------------|------------------|-----------------|
| Initial Access | T1105 | Ingress Tool Transfer | Malicious DLL delivered via SMB using Print Spooler service | Security Event ID 5145, Sysmon ID 11 |
| Execution | T1569.002 | Service Execution | Payload executed through `spoolsv.exe` and `rundll32.exe` | Sysmon process creation |
| Defense Evasion | T1036 | Masquerading | DLL disguised as printer driver and placed in trusted directory | Sysmon file creation |
| Command and Control | T1071.001 | Application Layer Protocol: Web | Reverse shell over outbound TCP 443 | Sysmon ID 3, PCAP |
| Discovery | T1033 | System Owner/User Discovery | `whoami` executed to confirm SYSTEM privileges | PCAP |

This table provides a condensed reference suitable for reporting, detection validation, and technique tracking across multiple investigations.

---

## Detection and Control Relevance

Mapping behaviors to MITRE ATT&CK supports defensive operations by:

- Highlighting the need to monitor SMB access to `spoolss` named pipes
- Supporting alerting on non-standard DLL creation in Print Spooler directories
- Identifying service-initiated execution of user-controlled DLLs
- Reinforcing correlation of service activity with outbound network connections

Detection opportunities and preventive control recommendations associated with these techniques are documented in:

- `detection-artifact-report.md`  
- `detection-and-hardening-recommendations.md`

---

## Notes and Assumptions

- All techniques are mapped solely based on behaviors confirmed in logs and packet capture data reviewed during this investigation.
- No exploit code analysis was performed; mapping focuses on post-exploitation observable behaviors.
- No lateral movement or credential theft was observed within scope.

This mapping reflects how ATT&CK is commonly applied during host-based service abuse investigations using log-driven reconstruction workflows.
