# 05 - Detection Logic and IOCs

## Overview

This document consolidates the detection opportunities, Indicators of Compromise (IOCs), and threat hunting methodologies identified during the Windows Event Logs & Finding Evil investigations.

The analysis covered:

•	DLL Hijacking

•	Unmanaged PowerShell Execution

•	Process Injection

•	LSASS Credential Dumping

•	Suspicious Logon Activity

•	Strange Parent-Child Relationships

The objective is to transform investigation findings into reusable detection logic suitable for SOC operations, threat hunting, and SIEM alert development.

The detection concepts presented below are derived from the observed lab telemetry. They represent investigative starting points and would require testing, baseline validation, and false-positive tuning before operational deployment.

## 1. DLL Hijacking Detection

### Attack Summary

The investigation identified suspicious DLL loading behaviour consistent with DLL Search Order Hijacking. **Dism.exe**, executing from **C:\ProgramData**, loaded an unsigned **DismCore.dll** from the same directory.

### Relevant Sysmon Event IDs

| Event ID | Event | Purpose |
|----------|-------|----------|
| 7 | Image Loaded | Detect DLL loading activity |

### Detection Logic

Monitor for:

•	Unsigned DLLs

•	DLLs loaded from user-writable directories

•	Executables loading DLLs from unexpected locations

### PowerShell Hunting Query

```powershell
Get-WinEvent -Path "DLLHijack.evtx" |
Where-Object {$_.Id -eq 7}
``` 

### Focus on Unsigned DLLs

```powershell
Get-WinEvent -Path "DLLHijack.evtx" |
Where-Object {$_.Id -eq 7} |
Where-Object {$_.Properties[12].Value -like "false"}
```
The positional index **Properties[12]** should be verified against the Sysmon Event ID 7 schema before applying this query to other datasets.

### IOC List

| IOC Type | Value |
|-----------|-------|
| Process | Dism.exe |
| DLL | DismCore.dll |
| Signature | False |
| Location | ProgramData |

**Detection context**: The suspicious indicator is the combination of the process path, DLL path, and unsigned signature status. These filenames alone are not malicious IOCs.

### Sigma Detection Concept

The original concept is too broad and would generate alerts for many legitimate unsigned DLLs. A more targeted Sigma-style

## 2. Unmanaged PowerShell Detection

### Attack Summary

PowerShell was executed without powershell.exe.

Instead, a legitimate Windows process hosted the .NET CLR and executed PowerShell code internally.

Investigation identified:

Process:
Calculator.exe

### Relevant Sysmon Event IDs

| Event ID | Event | Purpose |
|----------|-------|----------|
| 7 | Image Loaded | Detect DLL loading activity |

### Detection Logic

Look for:

    - clr.dll

    - clrjit.dll

    - System.Management.Automation.dll

being loaded by unusual processes.

### PowerShell Hunting Query

```powershell
Get-WinEvent -Path "PowerShellExec.evtx" |
Where-Object {$_.Properties[5].Value -like "*clr.dll*"}
``` 

### IOC List 

| IOC Type | Value |
|-----------|-------|
| Process | Calculator.exe |
| Module | clr.dll |
| Module | clrjit.dll |
| Module | System.Management.Automation.dll |

### High-Fidelity Alert

Generate alert when:

Process != powershell.exe

AND

ImageLoaded = clr.dll

### Sigma Detection Concept

title: Suspicious CLR Load

detection:

selection:
  ImageLoaded: "*clr.dll"

filter:
  Image:
    - "*powershell.exe"

condition:
  selection and not filter

## 3. Process Injection Detection

### Attack Summary

The attacker injected PowerShell code into Calculator.exe.

Investigation identified:

Injector:
rundll32.exe

Target:
Calculator.exe

### Relevant Sysmon Event IDs

| Event ID | Event | Purpose |
|----------|-------|----------|
| 8 | CreateRemoteThread | Detect remote thread creation and process injection |
| 10 | Process Access | Identify cross-process memory access |

### Detection Logic

Monitor:

CreateRemoteThread

Process Injection

Cross-process memory manipulation

### PowerShell Hunting Query

```powershell
Get-WinEvent -FilterHashtable @{
Path="PowerShellExec.evtx"
ID=8
}
``` 

### IOC List

| IOC Type | Value |
|-----------|-------|
| Source Process | rundll32.exe |
| Target Process | Calculator.exe |

### Suspicious Pattern

rundll32.exe

↓

Calculator.exe

↓

CLR Loaded

↓

PowerShell Executed

### Sigma Detection Concept

title: Process Injection

logsource:
  product: windows

detection:
  selection:
    EventID: 8

condition: selection

## 4. LSASS Credential Dumping Detection

### Attack Summary

A credential dumping operation targeted LSASS memory.

Investigation identified:

ProcessHacker.exe

accessing:

lsass.exe

with elevated permissions.

### Relevant Sysmon Event IDs

| Event ID | Event | Purpose |
|----------|-------|----------|
| 10 | Process Access | Detect access to LSASS memory |

### Detection Logic

Monitor:

TargetImage = lsass.exe

combined with:

GrantedAccess

values indicating full memory access.

### PowerShell Hunting Query

```powershell
Get-WinEvent -FilterHashtable @{
Path="LsassDump.evtx"
ID=10
}
``` 

### Filter for LSASS

```powershell
Get-WinEvent -FilterHashtable @{
Path="LsassDump.evtx"
ID=10
} |
Where-Object {$_.Properties[8].Value -like "*lsass*"}
``` 

### IOC List 

| IOC Type | Value |
|-----------|-------|
| Source Process | ProcessHacker.exe |
| Target | lsass.exe |
| GrantedAccess | 0x1FFFFF |

### Sigma Detection Concept

title: LSASS Memory Access

detection:

selection:
  TargetImage: "*lsass.exe"

condition:
  selection

## 5. Post-Dump Logon Review

### Attack Summary

Following credential dumping activity, investigators searched for evidence of credential abuse.

Security logs were reviewed for:

4624
Successful Logons

after the dump timestamp.

### Relevant Windows Event IDs

| Event ID | Event | Purpose |
|----------|-------|----------|
| 4624 | Successful Logon | Identify successful authentication events |
| 4625 | Failed Logon | Detect failed authentication attempts |
| 4648 | Explicit Credentials | Detect use of alternate credentials |
| 4672 | Special Privileges Assigned | Identify privileged logon sessions |

### Investigation Result

No malicious logon activity was identified following the credential dumping event.

### Detection Opportunities

Alert on:
- Event ID 4624
- Logon Type 3
- Logon Type 10
- Administrator account authentication
- Authentication immediately following LSASS access

### IOC Indicators

| IOC | Description |
|------|-------------|
| Dump Time | Timestamp of the LSASS credential dumping event |
| LSASS Access Event | Sysmon Event ID 10 targeting `lsass.exe` |
| Follow-Up Monitoring | Windows Event IDs 4624, 4625, 4648 and 4672 |

## 6. Strange Parent-Child Relationship Detection

### Attack Summary

Process creation analysis revealed:

WerFault.exe

spawning:

cmd.exe

which executed:

cmd.exe /c whoami

### Relevant Sysmon Event IDs

| Event ID | Event | Purpose |
|----------|-------|----------|
| 1 | Process Creation | Analyze parent-child process relationships |

### Detection Logic

Monitor unexpected parent-child combinations.

Examples:

WerFault.exe → cmd.exe

WerFault.exe → powershell.exe

Excel.exe → cmd.exe

Outlook.exe → powershell.exe

winword.exe → rundll32.exe

### PowerShell Hunting Query

```powershell
Get-WinEvent -Path "StrangePPID.evtx" `
-FilterXPath "*[System[EventID=1]]"
```

### Focus on CMD

```powershell
Get-WinEvent -Path "StrangePPID.evtx" `
-FilterXPath "*[System[EventID=1]]" |
Where-Object {$_.Properties[4].Value -like "*cmd*"}
``` 

### IOC List 

| IOC Type | Value |
|-----------|-------|
| Parent | WerFault.exe |
| Child | cmd.exe |
| Command | cmd.exe /c whoami | 
 
### Sigma Detection Concept

title: Suspicious Parent Child

detection:

parent:
  ParentImage: "*WerFault.exe"

child:
  Image: "*cmd.exe"

condition:
  parent and child

## Consolidated IOC Summary

### Processes

| Processes |
|-----------|
| Dism.exe |
| Calculator.exe |
| rundll32.exe |
| ProcessHacker.exe |
| WerFault.exe |
| cmd.exe |

### DLLs

| DLLs |
|------|
| DismCore.dll |
| clr.dll |
| clrjit.dll |
| System.Management.Automation.dll |

### Targets

| Targets |
|---------|
| lsass.exe |

### Commands

| Commands |
|----------|
| cmd.exe /c whoami |

### Event IDs

| Event ID | Description |
|----------|-------------|
| 1 | Process Create |
| 7 | Image Load |
| 8 | CreateRemoteThread |
| 10 | Process Access |
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4648 | Explicit Credentials |
| 4672 | Special Privileges |

## SOC Analyst Takeaways

The investigations demonstrate several high-value detection opportunities:

•	Unsigned DLL loading
•	CLR loading in unexpected processes
•	Process injection activity
•	LSASS memory access
•	Post-compromise authentication events
•	Parent-child anomalies

Together, these detections provide strong coverage against common attacker techniques including:

| ATT&CK ID | Technique |
|------------|------------------------------|
| T1574 | DLL Hijacking |
| T1055 | Process Injection |
| T1059 | PowerShell |
| T1003 | Credential Dumping |
| T1078 | Valid Accounts |
| T1036 | Masquerading |

This detection logic can be directly translated into SIEM rules, Sigma detections, Sysmon monitoring, and threat hunting playbooks for SOC operations.

## Operational Recommendations

Based on the investigation findings, defenders should prioritize monitoring:

•	Unsigned DLL loading
•	CLR initialization within unexpected processes
•	Cross-process memory access
•	LSASS access events
•	Post-compromise authentication activity
•	Abnormal parent-child process relationships

Combining these detections significantly improves visibility into post-exploitation techniques commonly observed in Windows environments.
