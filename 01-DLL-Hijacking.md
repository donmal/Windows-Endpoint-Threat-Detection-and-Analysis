# 01 - DLL Hijacking Investigation

## Executive Summary

This investigation focuses on identifying a DLL Hijacking attack through Windows Sysmon logs.
DLL Hijacking is a technique where an attacker abuses the Windows DLL search order by placing a malicious Dynamic Link Library (DLL) in a location that will be searched before the legitimate DLL. When the victim application starts, it loads the attacker-controlled DLL and executes malicious code under the context of the application.
The provided evidence consisted of Windows Event Logs located in:
C:\Logs\DLLHijack
Using Sysmon Image Load events (Event ID 7), the investigation identified an unsigned DLL being loaded by a suspicious executable. Analysis of the associated process revealed that Dism.exe was responsible for triggering the DLL hijacking attack.
This investigation demonstrates how defenders can leverage Sysmon Event ID 7, Event Viewer, and PowerShell-based log analysis to identify malicious DLL loading behavior and reconstruct the execution chain.

## Investigation Objectives
This investigation aimed to:
•	identify abnormal DLL loading behaviour within Sysmon telemetry; 
•	determine whether unsigned modules were executed; 
•	identify the responsible process; 
•	validate findings using multiple investigation techniques; 
•	document detection opportunities for future monitoring.

## Background

### What Is DLL Hijacking?

DLL Hijacking is a technique in which an application loads a malicious Dynamic Link Library (DLL) instead of the legitimate library it was intended to use. This occurs when an attacker places a malicious DLL in a location that is searched before the legitimate one within the Windows DLL search order.
Windows typically searches for DLLs using locations such as:
•	Application Directory 
•	System32 
•	System 
•	Windows Directory 
•	Current Working Directory 
•	PATH Directories 
If an attacker can place a malicious DLL earlier in the search order, the application may unintentionally execute attacker-controlled code.

### Why Attackers Use DLL Hijacking

DLL Hijacking provides several advantages to adversaries:
•	Code execution through trusted applications 
•	Persistence opportunities 
•	Privilege escalation opportunities 
•	Defense evasion 
•	Blending into legitimate application behavior 
Because execution originates from a legitimate executable, DLL Hijacking can be difficult to detect without visibility into module loading events such as Sysmon Event ID 7.

## Investigation Scenario

During routine monitoring, the SOC received a Sysmon log collection from a Windows workstation after suspicious application behavior was reported. Initial indicators suggested that a legitimate executable may have loaded an untrusted Dynamic Link Library (DLL), potentially indicating DLL Search Order Hijacking.
The objective of this investigation was to identify the affected process, determine whether an unsigned DLL was loaded, and reconstruct the execution sequence.

## Data Sources

| Source | Description |
|---------|-------------|
| `C:\Logs\DLLHijack\DLLHijack.evtx` | Primary Sysmon event log used throughout the investigation |
| Sysmon Operational Log | Windows telemetry source |
| Event ID 7 | Image Load events used to identify suspicious DLL loading |

## Why Event ID 7 Matters

Sysmon Event ID 7 records every DLL or module loaded by a running process. Since DLL Hijacking relies on malicious DLL loading rather than malicious process creation, this event provides critical visibility into module-loading behaviour. Event ID 7 exposes valuable attributes including the loading process, DLL path, digital signature status, hashes, and file metadata, making it one of the most effective telemetry sources for detecting DLL Search Order Hijacking.

## Investigation Methodology

The investigation was performed using two approaches:
1.	PowerShell Log Analysis
2.	Event Viewer Validation
Both methods should produce identical findings.

## Phase 1 – PowerShell Analysis

### Reviewing the Log File

Using PowerShell:
Get-WinEvent -Path 'C:\Logs\DLLHijack\DLLHijack.evtx'
This loads all events from the supplied log.
However, Event ID 7 is the primary event of interest.

### Filtering for DLL Load Events

Query:
Get-WinEvent -Path 'C:\Logs\DLLHijack\DLLHijack.evtx' |
Where-Object {$_.Id -eq 7}
Purpose:
Return only Image Load events.
This removes unrelated activity and focuses exclusively on DLL loading.

### Why Unsigned DLLs Matter

Legitimate Windows DLLs are typically signed by Microsoft.
Example:
Signed = True
Malicious DLLs often appear as:
Signed = False
This makes unsigned DLLs an excellent hunting indicator.

### Hunting for Unsigned DLLs

The following PowerShell query filters Sysmon Event ID 7 entries and returns unsigned DLL load events.

```powershell
Get-WinEvent -Path 'C:\Logs\DLLHijack\DLLHijack.evtx' |
Where-Object {$_.Id -eq 7} |
Where-Object {$_.Properties[12].Value -like "false"} |
Format-List
```

**Purpose:** Return DLL load events where `Signed = False`, significantly reducing the investigation scope.

### Understanding Property 12

Within Sysmon Event ID 7, the **Signed** attribute is stored as **EventData Property 12**.

Filtering on this field allows investigators to rapidly isolate unsigned DLLs, significantly reducing the number of events requiring manual review.

The following filter:

```powershell
$_.Properties[12].Value -like "false"
```

returns DLL load events where the loaded module is not digitally signed.

### Discovery of Suspicious DLL Activity

The filtered results revealed a suspicious Image Load event.

Key fields included:

Image:
C:\ProgramData\Dism.exe

and

ImageLoaded:
C:\ProgramData\DismCore.dll

along with:

Signed:
False

This combination immediately stood out.

At this stage, multiple indicators converged, suggesting that the observed activity was unlikely to represent legitimate software execution.

### Why This Event Is Suspicious

Several indicators were present:

- Unsigned DLL

Signed = False

Legitimate Microsoft DLLs are typically signed.

- Suspicious Location

C:\ProgramData\

ProgramData is writable and frequently abused by attackers.

- DLL Loaded by an Executable

The process:

Dism.exe

loaded:

DismCore.dll

from the same suspicious location.

## Attack Timeline

The observed sequence appears as:

Malicious DLL Placed
            ↓
Dism.exe Executed
            ↓
Dism.exe Searches for DLL
            ↓
Loads DismCore.dll
            ↓
Unsigned DLL Executes
            ↓
Malicious Code Runs

This behavior is consistent with DLL Search Order Hijacking.

## Phase 2 – Event Viewer Validation

After identifying the suspicious DLL load event through PowerShell, the findings were independently validated using Event Viewer.

The saved Sysmon log located at:

C:\Logs\DLLHijack\DLLHijack.evtx

was opened and filtered to display only **Event ID 7** entries. This manual validation confirmed the same unsigned DLL loading activity previously identified through PowerShell analysis.

### Reviewing Event Details

The General tab revealed:

Signed: False

This confirmed the PowerShell findings.

### XML Validation

Switching to:

Details
    ↓
XML View

revealed:

<Data Name="Image">
C:\ProgramData\Dism.exe
</Data>

<Data Name="ImageLoaded">
C:\ProgramData\DismCore.dll
</Data>

<Data Name="Signed">
false
</Data>

This provides direct evidence of:
•	The process
•	The DLL
•	The unsigned status

### Determining the Responsible Process

The **Image** field identified the executable responsible for loading the malicious DLL.

This field confirmed that **Dism.exe** initiated the DLL loading sequence, making it the process directly associated with the observed DLL Hijacking behaviour.

## Evidence Summary

| Evidence | Value | Significance |
|----------|-------|--------------|
| Event ID | 7 | Sysmon Image Load event |
| Process | `Dism.exe` | Executable responsible for loading the DLL |
| Loaded DLL | `DismCore.dll` | Unsigned DLL loaded by the process |
| Signature Status | `False` | Indicates the DLL was not digitally signed |
| Location | `C:\ProgramData\` | User-writable directory commonly abused by attackers |

## MITRE ATT&CK Mapping

| Category | Mapping |
|----------|---------|
| Technique | T1574.001 – DLL Search Order Hijacking |
| Tactic | TA0003 – Persistence |
| Tactic | TA0004 – Privilege Escalation |
| Tactic | TA0005 – Defense Evasion |

## Detection Opportunities

### Sysmon Event ID 7 Monitoring

Monitor Image Load events where:

•	Signed=False
•	DLLs are loaded outside standard Windows directories
•	Event ID 7 correlates with Sysmon Event ID 1 (Process Creation)

## Suspicious DLL Locations

Alert when DLLs are loaded from:

-	ProgramData
-	Users
-	Temp
-	Downloads

or other user-writable directories.

### Baseline Trusted DLLs

Maintain allowlists for:

-	Microsoft-signed DLLs
-	Vendor-signed DLLs
-	Known-good libraries
-	Baseline DLL loading behaviour for commonly abused executables such as Dism.exe, rundll32.exe and regsvr32.exe.

## Screenshots

### Figure 1. PowerShell query isolating unsigned DLL loads.

PowerShell query identifying unsigned DLL loads.

![Figure 1. PowerShell query isolating unsigned DLL loads](images/dll-hijacking/figure1-powershell-query.png)

### Figure 2. Event Viewer displaying Sysmon Event ID 7.

Event Viewer filtered to Event ID 7.

![Figure 2. Event Viewer displaying Sysmon Event ID 7](images/dll-hijacking/figure2-event-viewer-eventid7.png)

### Figure 3. Event properties confirming an unsigned DLL.

General tab showing:

Signed: False

![Figure 3. General tab showing Signed=False](images/dll-hijacking/figure3-signed-false-general.png)

### Figure 4. XML evidence identifying Dism.exe as the loading process.

XML View displaying:

<Data Name="Image">
C:\ProgramData\Dism.exe
</Data>

![Figure 4. XML showing Dism.exe as the loading process](images/dll-hijacking/figure4-dism-image-xml.png)

### Figure 5. XML evidence confirming Signed=False. 

XML View displaying:

<Data Name="Signed">
false
</Data>

![Figure 5. XML showing Signed=False](images/dll-hijacking/figure5-signed-false-xml.png)

## Investigation Findings

•	Sysmon Event ID 7 successfully exposed suspicious DLL loading activity.
•	PowerShell filtering rapidly isolated unsigned DLL load events.
•	Dism.exe` loaded the unsigned `DismCore.dll`.
•	The DLL was executed from `C:\ProgramData\`, a user-writable directory commonly abused by attackers.
•	Manual validation using Event Viewer confirmed the PowerShell findings.
•	The observed behaviour was consistent with MITRE ATT&CK T1574.001 – DLL Search Order Hijacking.
•	The investigation successfully identified the executable responsible for the malicious DLL loading sequence.

## Investigation Outcome 

The investigation confirmed that Dism.exe loaded an unsigned DismCore.dll from C:\ProgramData, consistent with DLL Search Order Hijacking.

## Conclusion

This investigation demonstrated how Sysmon Image Load telemetry (Event ID 7) can be used to identify DLL Search Order Hijacking by combining PowerShell-based hunting with manual Event Viewer validation.

Correlating digital signature status, executable location, and module-loading behaviour enabled rapid identification of the malicious DLL and the responsible process.

These findings reinforce the value of module-load monitoring, digital signature validation, and layered investigation techniques as part of a mature Windows detection strategy.

