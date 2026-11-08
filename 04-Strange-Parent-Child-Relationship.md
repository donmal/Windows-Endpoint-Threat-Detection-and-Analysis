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

This investigation demonstrates how process creation telemetry can expose suspicious execution behaviour through abnormal parent-child relationships, even when the available evidence does not identify a malicious executable or payload.

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

The Parent Process Identifier (PPID) identifies the process recorded as the parent of a newly created process. Since process identifiers can be reused, analysts should correlate PPIDs with process creation timestamps and unique identifiers such as Sysmon ProcessGuid.

Correlating process names with their PPIDs enables investigators to reconstruct execution chains and detect abnormal parent-child relationships.

### Why Parent-Child Analysis Matters

Many attacks leave traces through abnormal process trees.

Security analysts assess whether observed parent-child relationships are consistent with expected application behaviour, system functionality and established process execution baselines.

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

The investigation was conducted using a provided Windows Sysmon event log dataset located at:

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

Sysmon Event ID 1 records detailed process creation telemetry, including executable names, command-line arguments, parent processes and process identifiers. 

These fields provide sufficient context to reconstruct process execution chains and identify abnormal parent-child relationships.

## Phase 1 – Event Viewer Analysis

### Loading the Log

Open:

C:\Logs\StrangePPID\StrangePPID.evtx

The investigation began by reviewing StrangePPID.evtx within Event Viewer.

### Filtering Events

Only Sysmon Event ID 1 (Process Creation) events were reviewed to focus the investigation on process execution activity. 

This reduced the dataset and allowed rapid identification of suspicious process creation events.

### Initial Findings

Only a small number of process creation events were observed.

The limited number of recorded events allowed the investigation to focus on individual process execution relationships and associated command-line activity.

### Suspicious Event Discovery

One event revealed:

Image:
C:\Windows\System32\cmd.exe

and

CommandLine:
cmd.exe /c whoami

### Command Execution Analysis

The command:

whoami

is commonly used by attackers to:

•	Identify privileges

•	Confirm execution

•	Verify access level

•	Test code execution

Although **whoami** is a legitimate Windows utility, its execution through **cmd.exe** under an unexpected parent process can indicate reconnaissance or validation of command execution.

### Understanding cmd.exe /c

The `/c` argument instructs cmd.exe to execute the specified command and terminate immediately after completion, making it a common choice for short-lived command execution.

### Security Implications of Short-Lived Command Execution

Short-lived command interpreters reduce the attacker's footprint and frequently appear during reconnaissance, validation of code execution and privilege verification.

However, short-lived shell execution is not inherently malicious and should be evaluated alongside parent process identity, command-line arguments and surrounding telemetry.

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

The query relies on the positional event property **Properties[4]**, which should be validated against the Sysmon event schema. In standard Sysmon Event ID 1 records, this property commonly corresponds to the process image path. Filtering by named event fields would improve reliability across different Sysmon configurations.

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

The **whoami** command was executed through **cmd.exe**; it is shown as a command in the execution chain rather than a separately confirmed child process.

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

This relationship warrants investigation because Windows Error Reporting does not ordinarily require launching a command interpreter to execute user-discovery commands.

## Investigation Outcome

The investigation identified:

- Parent Process: WerFault.exe
- Child Process: cmd.exe
- Executed Command: whoami

Although WerFault.exe initiated the execution chain, cmd.exe was the process responsible for executing the command.

The observed process relationship was consistent with suspicious command execution, but the available evidence did not independently establish the initial execution mechanism or confirm malicious intent.

## Attack Timeline

### Stage 1

The process creation event identified the recorded parent process:

WerFault.exe

### Stage 2

Child process spawned.

cmd.exe

### Stage 3

Command executed.

whoami

### Stage 4

The **/c** argument instructed **cmd.exe** to terminate after executing the specified command. A separate process termination event would be required to confirm the actual exit.

## Detection Opportunities

### Event ID 1 Monitoring

Monitor:

- ParentImage
  
- Image

- CommandLine

relationships.

Correlate these fields with **ProcessGuid**, **ParentProcessGuid** and process creation timestamps to improve process-tree reconstruction.

### WerFault Abuse

Alert on:

WerFault.exe

launching:

- cmd.exe
  
- powershell.exe
  
- wscript.exe
  
- cscript.exe
  
- rundll32.exe

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

Detection logic should prioritize unusual parent-child combinations alongside suspicious command-line activity to reduce false positives from legitimate administrative operations.

## MITRE ATT&CK Mapping

| MITRE ATT&CK Technique | Technique ID | Investigation Relevance |
|-------------------------|--------------|--------------------------|
| Command and Scripting Interpreter | T1059 | Execution of command interpreters |
| Windows Command Shell | T1059.003 | Execution of cmd.exe |
| System Owner/User Discovery | T1033 | Discovery using whoami |

**Analytical Note**: T1059.003 and T1033 are the most directly relevant techniques because the observed event contains **cmd.exe /c whoami**. T1057 (Process Discovery) is not supported by the documented command, which identifies the current user rather than enumerating running processes.

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

- The observed activity aligned with MITRE ATT&CK techniques T1059.003 (Windows Command Shell) and T1033 (System Owner/User Discovery).

## Conclusion

This investigation demonstrates the value of parent-child process analysis during threat hunting and incident response.

Sysmon Event ID 1 telemetry exposed suspicious command execution through an abnormal parent-child process relationship, without requiring direct evidence of a malicious executable.

The investigation revealed that WerFault.exe launched cmd.exe, which executed a temporary reconnaissance command (whoami) using the **/c** argument to terminate after command execution. 

Such behavior highlights why SOC analysts should continuously monitor unusual parent-child relationships, as attackers frequently abuse trusted Windows binaries to hide malicious execution and evade traditional detections.
