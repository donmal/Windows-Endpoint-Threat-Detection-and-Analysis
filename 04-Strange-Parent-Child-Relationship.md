# 04 - Strange Parent Child Relationship 

## Executive Summary 

This investigation focuses on identifying malicious or suspicious process execution by analyzing abnormal parent-child process relationships within Windows event logs.

Attackers frequently abuse legitimate Windows processes to execute commands while attempting to blend into normal operating system activity. One common detection strategy used by SOC analysts is identifying unusual Parent Process ID (PPID) relationships.

The supplied evidence was located in:

C:\Logs\StrangePPID

Analysis of Sysmon Process Creation events revealed that:

•	WerFault.exe spawned cmd.exe
•	The command executed was:

cmd.exe /c whoami

•	This execution chain is highly unusual
•	WerFault.exe is not expected to launch command shells
•	The activity indicates temporary command execution through an abnormal parent-child relationship

This investigation demonstrates how process creation telemetry can expose attacker tradecraft even when no malware is dropped to disk.

## Investigation Objectives

The goals of this investigation were:

•	Analyze StrangePPID.evtx
•	Understand Parent Process relationships
•	Identify abnormal process trees
•	Investigate suspicious command execution
•	Reconstruct attacker activity
•	Map activity to MITRE ATT&CK
•	Develop detection opportunities

## Background

### Parent-Child Process Relationships

Every process created in Windows has a parent process responsible for its creation. Examining these parent-child relationships allows defenders to identify abnormal execution chains that frequently indicate malicious activity.

### Parent Process Identifier (PPID)

The Parent Process Identifier (PPID) uniquely identifies the process responsible for creating a child process. Correlating process names with their PPIDs enables investigators to reconstruct execution chains and detect abnormal parent-child relationships.

### Why Parent-Child Analysis Matters

Many attacks leave traces through abnormal process trees.
Security analysts often detect malicious activity by asking:
Does this parent-child relationship make sense?

### Suspicious Parent-Child Relationships

Abnormal parent-child relationships frequently indicate malicious execution. Examples include Office applications spawning command interpreters, scripting engines or administrative tools that are not normally launched during standard user activity.

## What Is WerFault.exe?

WerFault.exe (Windows Error Reporting) is a legitimate Windows process located at:

`C:\Windows\System32\WerFault.exe`

It is responsible for collecting crash information, generating diagnostic reports and submitting error data to Microsoft. Under normal circumstances, WerFault.exe is not expected to launch command interpreters or other interactive processes.

## Unexpected WerFault Behaviour

During the investigation, WerFault.exe was observed spawning cmd.exe, producing the following execution chain:

WerFault.exe
      ↓
cmd.exe

This behavior is inconsistent with the normal functionality of Windows Error Reporting and represents an abnormal parent-child relationship requiring further investigation.

## Investigation Scenario

The SOC receives logs from:

C:\Logs\StrangePPID

The investigation focused on determining whether abnormal parent-child process relationships indicated temporary attacker-controlled command execution.

## Data Sources

Primary source:

C:\Logs\StrangePPID\StrangePPID.evtx

Relevant Sysmon Event:

| Event ID | Source | Purpose |
|----------|--------|---------|
| 1 | Sysmon | Process Creation |

## Why Event ID 1?

Sysmon Event ID 1 records detailed process creation telemetry, including executable names, command-line arguments, parent processes and process identifiers. These fields provide sufficient context to reconstruct process execution chains and identify abnormal parent-child relationships.

## Phase 1 – Event Viewer Analysis

### Loading the Log

Open:

C:\Logs\StrangePPID\StrangePPID.evtx

The investigation began by reviewing StrangePPID.evtx within Event Viewer.

### Filtering Events

Only Sysmon Event ID 1 (Process Creation) events were reviewed to focus the investigation on process execution activity. This reduced the dataset and allowed rapid identification of suspicious process creation events.

### Initial Findings

Only a small number of process creation events were observed.
This immediately narrows the investigation scope.

### Suspicious Event Discovery

One event revealed:

Image:
C:\Windows\System32\cmd.exe

and

CommandLine:
cmd.exe /c whoami

### Why Is This Interesting?

The command:

whoami

is commonly used by attackers to:

•	Identify privileges
•	Confirm execution
•	Verify access level
•	Test code execution

### Understanding cmd.exe /c

The `/c` argument instructs cmd.exe to execute the specified command and terminate immediately after completion, making it a common choice for short-lived command execution.

### Why Attackers Like It

Short-lived command interpreters reduce the attacker's footprint and frequently appear during reconnaissance, validation of code execution and privilege verification.

## Phase 2 – PowerShell Analysis

To validate findings, PowerShell was used.

Query:

```powershell
Get-WinEvent -Path 'C:\Logs\StrangePPID\*' `
-FilterXPath "*[System[EventID=1]]" |
Where-Object {$_.Properties[4].Value -like "*cmd*"} |
fl
``` 

### Query Explanation

The PowerShell query filters Sysmon Process Creation (Event ID 1) events and searches for executions involving cmd.exe before displaying the complete event record for detailed analysis.

### Investigation Findings

The output showed:

Image:
C:\Windows\System32\cmd.exe

And:

CommandLine:
cmd.exe /c whoami

Most importantly:

ParentImage:
C:\Windows\System32\WerFault.exe

### Process Tree Reconstruction

Observed:

WerFault.exe
        ↓
cmd.exe
        ↓
whoami

### Why This Is Suspicious

WerFault normally handles:

Application Crashes

Not:
Command Execution

Therefore:

WerFault.exe
        ↓
cmd.exe

is an abnormal relationship.

## Investigation Outcome

The investigation identified:

- Parent Process: WerFault.exe
- Child Process: cmd.exe
- Executed Command: whoami

Although WerFault.exe initiated the execution chain, cmd.exe was the process responsible for executing the command.

## Attack Timeline

### Stage 1

Process creation occurs.

WerFault.exe

### Stage 2

Child process spawned.

cmd.exe

### Stage 3

Command executed.

whoami

### Stage 4

Process exits.

Temporary Execution Complete

## Detection Opportunities

### Event ID 1 Monitoring

Monitor:

ParentImage
ChildImage
CommandLine

relationships.

### WerFault Abuse

Alert on:

WerFault.exe

launching:

cmd.exe
powershell.exe
wscript.exe
cscript.exe
rundll32.exe

### Short-Lived Shells

Detect:

cmd.exe /c

and

powershell.exe -c

spawned from unusual parents.

### Parent-Child Baselines

Build baselines for:

Normal Parent Processes

and alert on deviations.

## MITRE ATT&CK Mapping

| MITRE ATT&CK Technique | Technique ID | Investigation Relevance |
|-------------------------|--------------|--------------------------|
| Command and Scripting Interpreter | T1059 | Execution of command interpreters |
| Windows Command Shell | T1059.003 | Execution of cmd.exe |
| Process Discovery | T1057 | Host reconnaissance through command execution |
| System Owner/User Discovery | T1033 | Discovery using whoami |

## Screenshots

### Figure 1. Opening StrangePPID.evtx in Event Viewer for process creation analysis.

Opening StrangePPID.evtx.

[INSERT SCREENSHOT]

### Figure 2. Event Viewer filtered to display Sysmon Event ID 1 (Process Creation) events.

Filtering Event ID 1.

[INSERT SCREENSHOT]

### Figure 3. Process creation event selected for detailed investigation.

Process Create event.

[INSERT SCREENSHOT]

### Figure 4. Event details identifying cmd.exe as the created process. 

Image = cmd.exe.

[INSERT SCREENSHOT]

### Figure 5. Command line showing execution of ‘cmd.exe /c whoami’.

CommandLine = cmd.exe /c whoami.

[INSERT SCREENSHOT]

### Figure 6. ParentImage field identifying WerFault.exe as the parent process.

ParentImage = WerFault.exe.

[INSERT SCREENSHOT]

### Figure 7. PowerShell Get-WinEvent output confirming the abnormal parent-child relationship.

PowerShell Get-WinEvent output.

[INSERT SCREENSHOT]

### Figure 8. Reconstructed process tree illustrating WerFault.exe spawning cmd.exe to execute whoami. 

Reconstructed process tree.

WerFault.exe
      ↓
cmd.exe
      ↓
whoami

[INSERT SCREENSHOT]

## Key Findings

•	Event ID 1 identified abnormal process creation activity.
•	WerFault.exe spawned cmd.exe.
•	cmd.exe executed the command `whoami`.
•	The execution chain represented temporary command execution.
•	Parent-child analysis exposed suspicious behaviour.

## Conclusion

This investigation demonstrates the value of parent-child process analysis during threat hunting and incident response.

Although no malware was written to disk, Event ID 1 telemetry exposed suspicious activity through an abnormal process relationship. The investigation revealed that WerFault.exe launched cmd.exe, which executed a temporary reconnaissance command (whoami) before terminating.

Such behavior highlights why SOC analysts should continuously monitor unusual parent-child relationships, as attackers frequently abuse trusted Windows binaries to hide malicious execution and evade traditional detections.
