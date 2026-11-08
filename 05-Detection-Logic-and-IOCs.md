# 05 - Detection Logic and IOCs

## Overview

This section consolidates the detection logic, investigation artifacts, and suspicious behavioral patterns identified during the Windows endpoint investigations.

The analysis focuses on six detection scenarios: DLL hijacking, unmanaged PowerShell execution, process injection, LSASS credential access, post-compromise authentication activity, and abnormal parent-child process relationships.

The objective is to translate observed endpoint activity into reusable detection opportunities for SOC monitoring, SIEM correlation, and threat hunting.


## 1. DLL Hijacking Detection

### Attack Summary

The investigation examined suspicious DLL loading activity involving Dism.exe and DismCore.dll, with a focus on identifying potential DLL search-order hijacking and unauthorized module loading.

### Relevant Sysmon Event IDs

| Event ID | Event | Purpose |
|----------|-------|----------|
| 7 | Image Loaded | Detect DLL loading activity |

### Detection Logic

Monitor unsigned or unexpectedly located DLLs loaded by trusted Windows processes, particularly when the module path deviates from expected system directories.

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

### Revised Sigma Detection Concept

The original detection concept is retained below in a structured Sigma format. This is an illustrative detection rule rather than a fully tuned production alert.

```yaml
title: Unsigned DLL Loaded by DISM
logsource:
  product: windows
  category: image_load

detection:
  selection:
    Image|endswith: '\Dism.exe'
    Signed: 'false'
  condition: selection
```

**Analyst Note**: An unsigned DLL alone does not confirm DLL hijacking. Correlation with the module path, expected application behavior, and additional process telemetry is necessary to reduce false positives.

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

**Query Improvement**: The original query uses a positional property index, which may not consistently reference the intended field. Filtering by the named **ImageLoaded** field is more reliable.

```powershell

Get-WinEvent -Path "PowerShellExec.evtx" |
Where-Object {
    $_.Id -eq 7 -and
    $_.ToXml() -match 'clr\.dll'
}
```

### IOC List 

| IOC Type | Value |
|-----------|-------|
| Process | Calculator.exe |
| Module | clr.dll |
| Module | clrjit.dll |
| Module | System.Management.Automation.dll |

**Analyst Note**: These modules are legitimate Windows/.NET components. Their presence is a behavioral indicator, not an IOC that independently confirms malicious activity.

### High-Interest Alert

Generate alert when:

Process != powershell.exe

AND

ImageLoaded = clr.dll

**Detection Refinement**: This condition is better treated as a hunting signal rather than a high-fidelity alert. Higher confidence requires correlating unexpected CLR loading with **System.Management.Automation.dll**, suspicious process ancestry, or other execution evidence.

### Revised Sigma Detection Concept

```yaml
title: Suspicious CLR Load in Calculator
logsource:
  product: windows
  category: image_load

detection:
  selection:
    Image|endswith: '\Calculator.exe'
    ImageLoaded|endswith:
      - '\clr.dll'
      - '\clrjit.dll'
      - '\System.Management.Automation.dll'
  condition: selection
```
This rule identifies relevant module-loading events for investigation. A stronger detection would correlate multiple module loads within the same process instance.

## 3. Process Injection Detection

### Attack Summary

The investigation identified process injection-related activity involving rundll32.exe and Calculator.exe, alongside CLR loading associated with unmanaged PowerShell execution.

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

- CreateRemoteThread

- Process Injection

- Cross-process memory manipulation

Correlate Sysmon Event ID 8 with Event ID 10 and subsequent module-loading activity to identify suspicious cross-process execution patterns.

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

**Analyst Note**: This sequence represents the suspected execution chain. Process injection and subsequent PowerShell execution should be confirmed through correlated telemetry rather than inferred from process names alone.

### Revised Sigma Detection Concept

```yaml
title: Suspicious Remote Thread Creation
logsource:
  product: windows
  category: create_remote_thread

detection:
  selection:
    SourceImage|endswith: '\rundll32.exe'
    TargetImage|endswith: '\Calculator.exe'
  condition: selection
```
This detection targets the observed source-target process combination rather than generating an alert for every CreateRemoteThread event.

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

**Query Improvement**: Replace the positional property index with named event-data filtering to avoid incorrectly matching unrelated fields.

```powershell
Get-WinEvent -FilterHashtable @{
    Path = "LsassDump.evtx"
    ID   = 10
} | Where-Object {
    $_.ToXml() -match '<Data Name="TargetImage">[^<]*\\lsass\.exe</Data>'
}
```

### IOC List 

| IOC Type | Value |
|-----------|-------|
| Source Process | ProcessHacker.exe |
| Target | lsass.exe |
| GrantedAccess | 0x1FFFFF |

**Analyst Note**: GrantedAccess **0x1FFFFF** indicates extensive process access rights and is a strong investigation signal when targeting LSASS. However, process access alone does not prove that credentials were successfully extracted.

### Revised Sigma Detection Concept

```yaml
title: Suspicious LSASS Access by Process Hacker
logsource:
  product: windows
  category: process_access

detection:
  selection:
    SourceImage|endswith: '\ProcessHacker.exe'
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: '0x1fffff'
  condition: selection
```

The rule focuses on the observed access pattern. Production deployment should account for legitimate administrative tools, alternate executable names, and other suspicious access masks.

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

Within the reviewed telemetry, no evidence of subsequent malicious authentication was identified. This finding does not exclude credential misuse outside the available log sources or investigation timeframe.

### Detection Opportunities

Correlate the following authentication indicators with the LSASS access timestamp:

- Event ID 4624
  
- Logon Type 3
  
- Logon Type 10
  
- Administrator account authentication
  
- Authentication immediately following LSASS access

Prioritize unusual privileged logons, remote authentication from unexpected hosts, and explicit credential usage. These indicators are more meaningful when combined than when alerted on individually.

### Investigation and Correlation Indicators

| IOC | Description |
|------|-------------|
| Dump Time | Timestamp of the LSASS credential dumping event |
| LSASS Access Event | Sysmon Event ID 10 targeting `lsass.exe` |
| Follow-Up Monitoring | Windows Event IDs 4624, 4625, 4648 and 4672 |

These entries represent investigation artifacts and correlation points rather than conventional indicators of compromise.

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

**Analyst Note**: Only the WerFault.exe → cmd.exe relationship is explicitly documented as an observed finding in this section. The remaining combinations are additional detection examples, not confirmed findings from this investigation.

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
**Query Improvement**: The revised query explicitly filters the **ParentImage** and **Image** event-data fields.

```powershell
Get-WinEvent -Path "StrangePPID.evtx" |
Where-Object {
    $_.Id -eq 1 -and
    $_.ToXml() -match '<Data Name="ParentImage">[^<]*\\WerFault\.exe</Data>' -and
    $_.ToXml() -match '<Data Name="Image">[^<]*\\cmd\.exe</Data>'
}
```

### IOC List 

| IOC Type | Value |
|-----------|-------|
| Parent | WerFault.exe |
| Child | cmd.exe |
| Command | cmd.exe /c whoami | 
 
### Revised Sigma Detection Concept

```yaml
title: Suspicious CMD Spawned by WerFault
logsource:
  product: windows
  category: process_creation

detection:
  selection:
    ParentImage|endswith: '\WerFault.exe'
    Image|endswith: '\cmd.exe'
  condition: selection
```
This rule identifies an unusual process relationship that warrants further investigation, especially when accompanied by reconnaissance commands or other suspicious child-process activity.

## Consolidated IOC Summary

The following artifacts were identified across the endpoint investigation scenarios. Legitimate Windows processes and modules are included as investigation indicators; their presence alone does not establish compromise.

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

Together, these detections provide strong coverage against visibility into behaviors associated with common attacker techniques including:

| ATT&CK ID | Technique |
|------------|------------------------------|
| T1574 | Hijack Execution Flow (parent technique) |
| T1055 | Process Injection |
| T1059 | Command and Scripting Interpreter (parent technique) |
| T1003 | OS Credential Dumping (parent technique) |
| T1078 | Valid Accounts |
| T1036 | Masquerading |

**ATT&CK Mapping Refinement**: More specific mappings include T1574.001 (DLL Search Order Hijacking), T1059.001 (PowerShell), and T1003.001 (LSASS Memory), where the observed evidence supports those techniques. T1078 and T1036 should be treated as contextual possibilities rather than confirmed findings in this section.

The documented detection concepts provide a foundation for developing SIEM correlation rules, Sigma detections, Sysmon monitoring strategies, and SOC threat hunting playbooks. Further validation, environment-specific tuning, and false-positive analysis are required before production deployment.

## Operational Recommendations

Based on the investigation findings, defenders should prioritize monitoring:

•	Unsigned DLL loading

•	CLR initialization within unexpected processes

•	Cross-process memory access

•	LSASS access events

•	Post-compromise authentication activity

•	Abnormal parent-child process relationships

Combining these detections significantly improves visibility into post-exploitation techniques commonly observed in Windows environments.

Additional operational priorities include validating Sysmon configurations, correlating endpoint and authentication telemetry, maintaining appropriate log retention, and tuning detection thresholds against legitimate administrative activity.
