# MITRE ATT&CK Mapping - Endpoint Cryptominer Infection Investigation (Suspicious Process Execution and Resource Abuse)

This document maps attacker behaviors observed during this investigation to MITRE ATT&CK tactics and techniques using direct evidence from SIEM alert metadata and Windows process creation telemetry.

All mappings are based on confirmed activity identified during analysis rather than inferred attacker intent or assumed tooling.

The purpose of this mapping is to support standardized incident classification, detection coverage validation, and alignment with threat modeling frameworks commonly used by security operations teams.

---

## How This Mapping Was Performed

Techniques were mapped by reviewing:

- SIEM alert metadata identifying the triggering executable
- Correlated Windows Security Event ID 4688 process creation logs
- Execution path, user context, and host attribution fields
- Detection rule logic used by the SIEM to flag mining-related activity

Each technique listed below references the specific investigative steps and artifacts that supported the classification.

---

## MITRE ATT&CK Mapping (Narrative View)

### Execution

#### User Execution (T1204)

**Observed Behavior**  
A suspicious executable named `cudominer.exe` was launched under the context of a standard user account (`Chris.Fort`) on host `HR_02`. The process was executed from a user-writable temporary directory rather than a trusted application path.

This behavior was confirmed during correlation of SIEM alert context with Windows process creation telemetry.

**Evidence Sources**  
- SIEM alert identifying `cudominer.exe` as the triggering process  
- Windows Security Event ID 4688 showing process execution  
- Execution path: `C:\Users\Chris.Fort\temp\cudominer.exe`  
- User context: `Chris.Fort`  
- Host: `HR_02`

**Why This Maps to ATT&CK**  
The attacker relied on execution of a binary within a user session rather than exploiting a service or automated system process. This aligns with ATT&CK’s User Execution technique, where malicious payloads depend on user-context execution to run.


### Impact

#### Resource Hijacking (T1496)

**Observed Behavior**  
The executed binary was identified by the SIEM detection rule as consistent with cryptocurrency mining behavior based on executable naming patterns and associated mining indicators.

Although full resource utilization metrics were not captured within the scope of the alert, the executable name and rule logic specifically targeted cryptomining activity.

**Evidence Sources**  
- SIEM correlation rule matching mining-related keywords (e.g., `miner`, `crypt`)  
- Executable name: `cudominer.exe`  
- Alert classification indicating potential cryptominer behavior

**Why This Maps to ATT&CK**  
Cryptocurrency mining malware is explicitly covered under ATT&CK’s Resource Hijacking technique, which involves unauthorized consumption of system resources for attacker benefit.

The execution of a known mining-related binary directly supports this classification.

---

## MITRE ATT&CK Mapping (Table View)

| Tactic | Technique ID | Technique Name | Evidence Summary | Evidence Source |
|--------|--------------|----------------|------------------|-----------------|
| Execution | T1204 | User Execution | Mining-related executable launched under standard user context from temp directory | SIEM alert, Event ID 4688 |
| Impact | T1496 | Resource Hijacking | Executable matched cryptomining detection logic and naming patterns | SIEM correlation rule |

This table provides a condensed reference suitable for reporting, detection validation, and technique tracking across multiple investigations.

---

## Detection and Control Relevance

Mapping behaviors to MITRE ATT&CK supports defensive operations by:

- Validating that endpoint telemetry captures user-context execution events  
- Highlighting detection opportunities for execution from user-writable directories  
- Supporting monitoring for cryptomining indicators prior to sustained resource impact  

Detection opportunities and preventive control recommendations associated with these techniques are documented in:

- `detection-artifact-report.md`  
- `detection-and-hardening-recommendations.md`

---

## Notes and Assumptions

- Techniques are mapped solely based on observable process execution and SIEM detection logic within scope of the alert investigation.
- No
