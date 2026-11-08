# 02 - Unmanaged PowerShell and Injection 

## Executive Summary 

This investigation focuses on identifying an Unmanaged PowerShell attack and the associated Process Injection technique used to execute malicious PowerShell code inside a legitimate Windows process.

Unlike traditional PowerShell execution, where commands are launched through powershell.exe, unmanaged PowerShell occurs when PowerShell functionality is loaded directly into another process through the .NET Common Language Runtime (CLR).

The supplied evidence was located in:

C:\Logs\PowerShellExec

Analysis of Sysmon logs revealed that:

•	Calculator.exe loaded the .NET runtime (clr.dll)

•	This indicated potential in-process PowerShell hosting or other managed .NET execution.

•	Further investigation identified a CreateRemoteThread event

•	**rundll32.exe** created a remote thread inside **Calculator.exe**, providing evidence consistent with process injection

•	The combined telemetry suggested a possible unmanaged PowerShell execution chain, although the supplied events did not independently confirm PowerShell commands being executed

This investigation demonstrates how defenders can use Sysmon Image Load events (Event ID 7) and CreateRemoteThread events (Event ID 8) to detect memory-based PowerShell attacks and process injection activity.

## Investigation Objectives 

The investigation objectives were to:

•	Analyze Sysmon telemetry from **PowerShellExec.evtx**

•	Identify evidence of unmanaged PowerShell execution

•	Determine which process hosted the CLR runtime

•	Determine how PowerShell code was introduced into the host process

•	Identify the source of the injection activity

•	Reconstruct the suspected attack chain

•	Map observed behavior to MITRE ATT&CK

•	Identify defensive detection opportunities

## Background 

### What Is Unmanaged PowerShell? 

Under normal circumstances, PowerShell code executes through **powershell.exe**, making it relatively easy for defenders to monitor script execution, command-line arguments, and child processes.

Unmanaged PowerShell differs significantly because the PowerShell engine is loaded directly into another process through the Microsoft .NET Common Language Runtime (CLR), allowing attackers to execute PowerShell code without launching **powershell.exe**. 

This technique reduces visibility and enables malicious activity to blend into legitimate Windows processes.

### Why Attackers Avoid powershell.exe

Attackers often attempt to evade detections by hosting PowerShell inside another process.

Instead of:

powershell.exe

they may use:

- Calculator.exe

- spoolsv.exe
  
- svchost.exe
  
- explorer.exe
  
- rundll32.exe

This approach:

•	Hides execution

•	Bypasses simple detections

•	Blends into legitimate activity

•	Reduces PowerShell visibility

### How PowerShell Runs Inside Another Process

PowerShell relies on Microsoft's .NET Framework.

To execute .NET code, a process must load:

clr.dll

CLR stands for:

Common Language Runtime

Unexpected CLR loading in processes that do not typically host managed code may indicate:

- .NET Execution
  
- PowerShell Hosting
  
- Malicious Code Execution

However, CLR loading alone is not sufficient to distinguish legitimate managed code execution from malicious PowerShell hosting.

## Investigatoin Scenario

The investigation was conducted using a provided Sysmon event log dataset to examine potentially suspicious CLR loading and process injection activity.

C:\Logs\PowerShellExec

The investigation focused on identifying evidence of unmanaged PowerShell execution and determining whether process injection had been used to host malicious code inside a legitimate Windows process.

## Data Sources

### Evidence Source

| Source | Description |
|---------|-------------|
| **PowerShellExec.evtx** | Primary Sysmon log analyzed during the investigation. |
| **Location** | `C:\Logs\PowerShellExec\PowerShellExec.evtx` |

### Relevant Sysmon Events

| Event ID | Event Name | Purpose |
|----------|------------|---------|
| **1** | Process Creation | Records newly created processes. |
| **7** | Image Loaded | Identifies DLLs and modules loaded into a process. |
| **8** | CreateRemoteThread | Detects remote thread creation associated with process injection. |

## Attack Overview

The observed telemetry supported the following suspected execution chain:

rundll32.exe

          ↓
          
CreateRemoteThread

          ↓
          
Calculator.exe

          ↓
          
Loads clr.dll

          ↓
          
PowerShell Executes

The remote thread creation and CLR loading were observable through Sysmon telemetry. Actual PowerShell execution would require additional evidence, such as PowerShell engine activity, relevant module loads, or script execution telemetry.

## Phase 1 – Detecting Unmanaged PowerShell

### Why Look for clr.dll?

PowerShell depends on the .NET runtime.

One useful indicator of managed .NET execution is the loading of:

clr.dll

If a process loads:

clr.dll

it gains the ability to execute .NET code.

## PowerShell Investigation

### Loading the Log

Get-WinEvent -Path 'C:\Logs\PowerShellExec\PowerShellExec.evtx'

This reads all events from the EVTX file.

### Searching for CLR Activity

The next step is identifying CLR loads.

Query:

Get-WinEvent -Path 'C:\Logs\PowerShellExec\PowershellExec.evtx' |
Where-Object {$_.Properties[5].Value -like "*clr.dll*"} |
Format-List

### Why This Query Works

The query:

```powershell
$_.Properties[5]
```

contains:

ImageLoaded

Filtering for:

clr.dll

returns processes loading the .NET runtime.

The property index should be validated against the Sysmon Event ID 7 schema. Filtering explicitly for Event ID 7 and the **ImageLoaded** field would make this detection more reliable across different datasets.

## Investigation Findings

The Event ID 7 analysis identified Calculator.exe loading clr.dll, indicating that the .NET Common Language Runtime had been initialized within the process.

Since in-process PowerShell hosting can rely on the CLR without launching **powershell.exe**, this observation warranted further investigation into possible unmanaged PowerShell activity within **Calculator.exe**.

## Figure 5 - CLR Loading in Calculator.exe 

![Figure 1 - CLR Loading in Calculator.exe](https://github.com/USERNAME/Windows-Endpoint-Threat-Detection-and-Analysis/blob/main/images/unmanaged-powershell/calculator-clr-loading.png?raw=true)

## Why Calculator.exe Is Suspicious

Calculator.exe is not expected to host managed .NET workloads during normal Windows operation.

The loading of **clr.dll** indicates that the Microsoft Common Language Runtime (CLR) was initialized inside the process, providing the capability to execute managed .NET code, including PowerShell.

Because Calculator.exe is not a typical host for CLR-based execution, this behavior represented a strong indicator of abnormal activity and warranted further investigation into possible code injection or unmanaged PowerShell execution.


## Evidence Summary

| Field | Value |
|-------|-------|
| **Event ID** | 7 |
| **Process** | Calculator.exe |
| **Loaded Module** | clr.dll |
| **Observed Activity** | CLR Loading |	

## Investigation Conclusion

The evidence confirmed that **Calculator.exe** loaded the CLR runtime, making it a potential host for unmanaged PowerShell or other managed .NET code.

This finding was established through Sysmon Event ID 7 and formed the basis for investigating potential process injection activity.

## Phase 2 – Process Injection Investigation

Following the identification of suspicious CLR loading, the investigation focused on the process associated with the activity:

Calculator.exe

The next objective was to identify any source process responsible for remote thread creation within **Calculator.exe**.

## What Is Process Injection?

Process Injection occurs when one process inserts code into another process.

Example:

Malicious Process

        ↓
        
Injects Code

        ↓
        
Legitimate Process

The legitimate process then executes attacker-controlled code.

### Why Attackers Use Injection

Benefits include:

•	Hiding malicious code

•	Running under trusted processes

•	Evading security products

•	Avoiding detection by parent-child monitoring

## Sysmon Event ID 8

Sysmon Event ID 8 records:

CreateRemoteThread

This occurs when one process creates a thread inside another process.

Remote thread creation is an important indicator of potential process injection, although legitimate applications may also create remote threads.

## Hunting for Injection Activity

PowerShell query:
```powershell
Get-WinEvent -FilterHashtable @{
Path='C:\Logs\PowershellExec\PowershellExec.evtx'
ID=8
} |
Where-Object {$_.Message -like "*Calculator.exe*"} |
Format-List
``` 
### What This Query Does

The query first filters for:

ID=8

Returns only:

CreateRemoteThread events.

It then searches the event message for:

Calculator.exe

filters for events targeting the identified victim process.

## Investigation Findings

The results showed:

SourceImage:
C:\Windows\System32\rundll32.exe

and

TargetImage:
C:\Users\Administrator\Desktop\Calculator.exe

### Figure 6 - Remote Thread Creation: rundll32.exe to Calculator.exe

![Figure 2 - rundll32.exe to Calculator.exe](https://github.com/USERNAME/Windows-Endpoint-Threat-Detection-and-Analysis/blob/main/images/unmanaged-powershell/rundll32-calculator-remote-thread.png?raw=true)

## Interpreting the Event

The CreateRemoteThread event identified:

**SourceImage**:
rundll32.exe

**TargetImage**:
Calculator.exe

This confirmed that **rundll32.exe** created a remote thread inside **Calculator.exe**, consistent with a potential process injection technique. The event alone did not establish the exact injected payload or confirm that unmanaged PowerShell subsequently executed.

## Attack Chain

Correlation of Sysmon Event IDs 7 and 8 supported the following suspected execution flow:

rundll32.exe

        │
        ▼
        
CreateRemoteThread

        │
        ▼
        
Calculator.exe

        │
        ▼
        
Load clr.dll

        │
        ▼
        
Unmanaged PowerShell Execution

The sequence is an analytical reconstruction. Event timestamps and additional process telemetry would be needed to confirm the precise ordering and relationship between the activities.

## Why rundll32.exe Is Commonly Abused

rundll32.exe is a legitimate Windows utility.

Attackers abuse it because:

•	Microsoft-signed

•	Trusted by Windows

•	Often allowed by application control

•	Frequently ignored by users

This makes it a popular LOLBIN.

## MITRE ATT&CK Mapping

| Technique | ATT&CK ID | Description |
|-----------|-----------|-------------|
| Process Injection | **T1055** | Injection of malicious code into another running process. |
| PowerShell | **T1059.001** | Execution of PowerShell commands through the .NET runtime. |
| Signed Binary Proxy Execution (Rundll32) | **T1218.011** | Abuse of Microsoft's signed rundll32.exe binary to execute malicious activity. |

Analytical Note: T1055 is supported as a suspected technique by the CreateRemoteThread telemetry. T1059.001 and T1218.011 are relevant hypotheses but would require further evidence of PowerShell execution and malicious use of **rundll32.exe** to be confirmed.

## Detection Opportunities

### Detect CLR Loading

Monitor Event ID 7 for:

clr.dll

loaded by:

• Calculator.exe

• notepad.exe

• explorer.exe

• spoolsv.exe

• svchost.exe

Prioritize unexpected CLR loading based on established process baselines rather than treating every CLR load as malicious.

### Detect CreateRemoteThread

Monitor:

Event ID 8

especially when:

The source process is unexpected for the target process, or when remote thread creation involves unusual process pairs.

### Detect LOLBIN Abuse

Alert on:

rundll32.exe

acting as the source process in:

CreateRemoteThread Events

Correlate these events with process command-line arguments, target process identity, loaded modules, and additional endpoint telemetry to reduce false positives.

## Screenshots

### Figure 1. PowerShell query identifying processes that loaded the .NET Common Language Runtime (clr.dll).

PowerShell query searching for clr.dll.

[INSERT SCREENSHOT]

### Figure 2. Query results showing Calculator.exe loading clr.dll, indicating unmanaged PowerShell execution.

Results showing Calculator.exe loading clr.dll.

[INSERT SCREENSHOT]

### Figure 3. Event Viewer validation of Sysmon Event ID 7 confirming CLR module loading.

Event Viewer validation of Event ID 7.

[INSERT SCREENSHOT]

### Figure 4. PowerShell query filtering Sysmon Event ID 8 to identify CreateRemoteThread activity.

PowerShell query searching Event ID 8.

[INSERT SCREENSHOT]

### Figure 5. CreateRemoteThread event identifying rundll32.exe as the source of the injection.

SourceImage = rundll32.exe.

[INSERT SCREENSHOT]

### Figure 6. CreateRemoteThread event confirming Calculator.exe as the target process.

TargetImage = Calculator.exe.

[INSERT SCREENSHOT]

## Key Findings 

•	CLR loading identified potential in-process PowerShell hosting.

•	Calculator.exe hosted managed code unexpectedly.

•	Sysmon Event ID 7 provided the initial evidence.

•	Sysmon Event ID 8 revealed remote thread creation consistent with potential process injection.

•	rundll32.exe performed CreateRemoteThread into Calculator.exe.

•	The attack potentially leveraged a trusted Microsoft LOLBIN.

•	Correlating Event IDs 7 and 8 enabled reconstruction of the suspected attack chain.

## Conclusion

This investigation demonstrated how memory-resident PowerShell attacks can be investigated through Sysmon telemetry even when attackers avoid using powershell.exe directly.

By identifying CLR loading inside **Calculator.exe** and correlating CreateRemoteThread events, the investigation established a suspicious relationship between **rundll32.exe** and **Calculator.exe**, consistent with potential process injection and unmanaged PowerShell hosting.

This case highlights the importance of monitoring CLR loading, CreateRemoteThread activity, and LOLBIN abuse when hunting advanced Windows threats.

Correlating Sysmon Image Load events with CreateRemoteThread telemetry provides valuable detection opportunities for identifying suspicious in-memory execution, particularly when traditional process-name-based monitoring does not reveal PowerShell activity.
