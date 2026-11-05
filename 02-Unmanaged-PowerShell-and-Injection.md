# 02 - Unmanaged PowerShell and Injection 

## Executive Summary 

This investigation focuses on identifying an Unmanaged PowerShell attack and the associated Process Injection technique used to execute malicious PowerShell code inside a legitimate Windows process.
Unlike traditional PowerShell execution, where commands are launched through powershell.exe, unmanaged PowerShell occurs when PowerShell functionality is loaded directly into another process through the .NET Common Language Runtime (CLR).
The supplied evidence was located in:
C:\Logs\PowerShellExec
Analysis of Sysmon logs revealed that:
•	Calculator.exe loaded the .NET runtime (clr.dll)
•	This indicates PowerShell execution within Calculator.exe
•	Further investigation identified a CreateRemoteThread event
•	rundll32.exe injected code into Calculator.exe
•	The injection enabled the execution of unmanaged PowerShell
This investigation demonstrates how defenders can use Sysmon Image Load events (Event ID 7) and CreateRemoteThread events (Event ID 8) to detect memory-based PowerShell attacks and process injection activity.

## Investigation Objectives 

The investigation objectives were to:
•	Analyze Sysmon telemetry from **PowerShellExec.evtx**
•	Identify evidence of unmanaged PowerShell execution
•	Determine which process hosted the CLR runtime
•	Determine how PowerShell code was introduced into the host process
•	Identify the source of the injection activity
•	Reconstruct the complete attack chain
•	Map observed behavior to MITRE ATT&CK
•	Identify defensive detection opportunities

## Background 

### What Is Unmanaged PowerShell? 

Under normal circumstances, PowerShell code executes through **powershell.exe**, making it relatively easy for defenders to monitor script execution, command-line arguments, and child processes.
Unmanaged PowerShell differs significantly because the PowerShell engine is loaded directly into another process through the Microsoft .NET Common Language Runtime (CLR), allowing attackers to execute PowerShell code without launching **powershell.exe**. This technique reduces visibility and enables malicious activity to blend into legitimate Windows processes.

### Why Attackers Avoid powershell.exe

Attackers often attempt to evade detections by hosting PowerShell inside another process.

Instead of:

powershell.exe

they may use:

Calculator.exe
spoolsv.exe
svchost.exe
explorer.exe
rundll32.exe

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

When analysts observe unexpected CLR loading inside unusual processes, it often indicates:

.NET Execution
PowerShell Hosting
Malicious Code Execution

## Investigatoin Scenario

During routine threat hunting, Sysmon logs from the following evidence source were analyzed:

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

The attack chain ultimately looked like:

rundll32.exe
          ↓
CreateRemoteThread
          ↓
Calculator.exe
          ↓
Loads clr.dll
          ↓
PowerShell Executes

## Phase 1 – Detecting Unmanaged PowerShell

### Why Look for clr.dll?

PowerShell depends on the .NET runtime.

One of the most reliable indicators is:

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

## Investigation Findings

The Event ID 7 analysis identified Calculator.exe loading clr.dll, indicating that the .NET Common Language Runtime had been initialized within the process.

Since unmanaged PowerShell relies on the CLR rather than powershell.exe, this represented a strong indicator of PowerShell execution occurring inside Calculator.exe.

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

The evidence confirmed that Calculator.exe was the process hosting unmanaged PowerShell execution.

This conclusion was based on CLR loading observed through Sysmon Event ID 7.

## Phase 2 – Process Injection Investigation

Now that the victim process is known:

Calculator.exe

the next objective becomes:

Who injected into Calculator.exe?

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

It is one of the strongest indicators of process injection.

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

Step 1:

ID=8

Returns only:

CreateRemoteThread events.

Step 2:

Calculator.exe

filters for events targeting the identified victim process.

## Investigation Findings

The results showed:

SourceImage:
C:\Windows\System32\rundll32.exe

and

TargetImage:
C:\Users\Administrator\Desktop\Calculator.exe

## Interpreting the Event

The CreateRemoteThread event identified:

**SourceImage**:
rundll32.exe

**TargetImage**:
Calculator.exe

This confirmed that rundll32.exe injected executable code into Calculator.exe before unmanaged PowerShell execution occurred.

## Attack Chain

The investigation reconstructed the following execution flow:

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

## Detection Opportunities

### Detect CLR Loading

Monitor Event ID 7 for:

clr.dll

loaded by:

Calculator.exe
notepad.exe
explorer.exe
spoolsv.exe
svchost.exe

### Detect CreateRemoteThread

Monitor:

Event ID 8

especially when:

SourceImage ≠ Parent Process

or when unusual process pairs appear.

### Detect LOLBIN Abuse

Alert on:

rundll32.exe

creating:

CreateRemoteThread Events

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

•	CLR loading identified unmanaged PowerShell execution.
•	Calculator.exe hosted managed code unexpectedly.
•	Sysmon Event ID 7 provided the initial evidence.
•	Sysmon Event ID 8 revealed process injection activity.
•	rundll32.exe performed CreateRemoteThread into Calculator.exe.
•	The attack leveraged a trusted Microsoft LOLBIN.
•	Correlating Event IDs 7 and 8 enabled reconstruction of the complete attack chain.

## Conclusion

This investigation demonstrated how memory-resident PowerShell attacks can be detected through Sysmon telemetry even when attackers avoid using powershell.exe directly.

By identifying CLR loading inside Calculator.exe and correlating CreateRemoteThread events, it was possible to reconstruct the full attack chain and determine that rundll32.exe injected code into Calculator.exe, which subsequently executed unmanaged PowerShell.

This case highlights the importance of monitoring CLR loading, CreateRemoteThread activity, and LOLBIN abuse when hunting advanced Windows threats.

The investigation demonstrates how correlating Sysmon Image Load events with CreateRemoteThread telemetry enables defenders to detect fileless PowerShell attacks even when traditional PowerShell process monitoring is bypassed.

