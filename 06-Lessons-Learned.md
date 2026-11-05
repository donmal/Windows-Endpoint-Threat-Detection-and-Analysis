# 06 - Lessons Learned 

## Executive Summary

The Windows Event Logs & Finding Evil investigations provided practical experience in identifying attacker activity using Windows Event Logs, Sysmon telemetry, Security Auditing logs, and process behavior analysis.

Throughout these investigations, multiple attack techniques were investigated, including:

•	DLL Hijacking
•	Unmanaged PowerShell Execution
•	Process Injection
•	Credential Dumping
•	Post-Compromise Authentication Analysis
•	Parent-Child Process Anomalies

While each scenario focused on a different attacker technique, they collectively reinforced a critical lesson:

Modern detection engineering relies on understanding process behavior, memory access patterns, execution chains, and event correlations rather than relying solely on malware signatures.

## Lesson 1: DLL Hijacking Often Looks Legitimate

### Initial Assumption

At first glance, the process involved in the DLL hijacking investigation appeared completely legitimate:

Dism.exe

Because DISM is a legitimate Microsoft utility, many analysts could mistakenly assume the activity is benign.

### What Actually Happened

The executable loaded:

DismCore.dll

from an unexpected location.

More importantly:

Signed = False

revealed that the DLL was not digitally signed.

This transformed an apparently normal process into a clear compromise indicator.

### Key Takeaway

Legitimate processes can become malicious when they load attacker-controlled modules.

SOC analysts should never trust a process solely because:

•	It has a legitimate name
•	It exists on every Windows system
•	It is Microsoft-signed

The surrounding context matters.

### Practical Detection Rule

Investigate:

- Sysmon Event ID 7 (Image Loaded)
- Unsigned DLLs
- DLLs loaded from non-standard or user-writable directories
- Unexpected DLL loading by trusted executables

## Lesson 2: PowerShell Does Not Need powershell.exe

### Initial Assumption

A common assumption is that PowerShell activity is always associated with powershell.exe.

### What Actually Happened

The investigation revealed:

Calculator.exe

loading:

clr.dll

and hosting PowerShell internally.

No visible PowerShell process was required.

### Why This Matters

Attackers frequently use:

PowerShell Hosting

PowerShell Runspaces

Reflective Loading

In-Memory Execution

to avoid traditional detections.

This technique is commonly referred to as:

Unmanaged PowerShell

or

PowerShell Without PowerShell.exe

### Key Takeaway

Detection strategies should prioritize behavioral indicators rather than relying solely on process names. Monitoring CLR libraries loaded by unexpected processes provides significantly stronger detection opportunities than searching exclusively for powershell.exe.

### Practical Detection Rule

Generate alerts when the following modules are loaded by unexpected processes:

- clr.dll
- clrjit.dll
- System.Management.Automation.dll

Particular attention should be given to Office applications, web browsers, utilities, and other processes not typically associated with PowerShell execution.

## Lesson 3: Process Injection Leaves Traces

### Initial Assumption

A common assumption is that process injection completely conceals malicious execution by running code inside legitimate processes.

### What Actually Happened

The investigation identified:

Source:
rundll32.exe

Target:
Calculator.exe

through:

Sysmon Event ID 8
(CreateRemoteThread)

### Why This Matters

Process injection attempts to:

•	Blend into trusted processes
•	Evade endpoint protection
•	Hide malicious execution

However, the injection process frequently leaves artifacts.

### Key Takeaway

Even when malicious code executes within a legitimate process, the injection activity itself frequently generates observable telemetry that can be leveraged for detection and investigation.

### Practical Detection Rule

Monitor:

- Sysmon Event ID 8 (CreateRemoteThread)
- Sysmon Event ID 10 (Process Access)
- Suspicious source-target process relationships indicative of process injection.

## Lesson 4: Credential Dumping Is Usually Observable

### Initial Assumption

A common assumption is that credential dumping can be performed without generating observable forensic evidence.

### What Actually Happened

The investigation identified ProcessHacker.exe accessing lsass.exe with a GrantedAccess value of 0x1FFFFF, indicating extensive permissions to read process memory. This level of access is commonly associated with credential dumping activity.

### Why This Matters

Many credential theft tools require:

•	Reading LSASS memory
•	Opening privileged handles
•	Extracting sensitive authentication material

These actions generate detectable events.

### Key Takeaway

Credential dumping frequently creates stronger forensic evidence than the actual credential abuse that follows

### Practical Detection Rule

Investigate LSASS access involving:

- TargetImage = lsass.exe
- High GrantedAccess values
- Unknown or untrusted processes
- Administrative utilities performing memory access

## Lesson 5: Not Every Login After an Attack Is Malicious

### Initial Assumption

A common assumption is that any successful logon occurring after credential dumping indicates credential abuse.

### What Actually Happened

After reviewing:

Event ID 4624

the observed login was:

SYSTEM

Logon Type 5

services.exe

which represented a normal service authentication event.

### Why This Matters

Many analysts generate false positives because they focus solely on timing.

A login occurring after an attack is not automatically malicious.

Context matters.

### Key Takeaway

Authentication events should always be evaluated within their operational context, including the user account, logon type, source system, and authentication method, before concluding that credential abuse has occurred.

### Practical Detection Rule

Prioritize investigation of:

- Event ID 4624 (Successful Logon)
- Logon Type 3 (Network)
- Logon Type 10 (Remote Interactive)
- Administrative account authentication
- Newly created user accounts

rather than treating every successful logon as suspicious.

## Lesson 6: Parent-Child Relationships Reveal Execution Chains

### Initial Assumption

A process may appear legitimate when viewed in isolation without considering its parent-child execution context.

### What Actually Happened

The investigation identified WerFault.exe spawning cmd.exe, which subsequently executed the command `cmd.exe /c whoami`. This abnormal parent-child relationship revealed temporary command execution initiated through an unexpected Windows process.

### Why This Matters

WerFault is normally used for:

Windows Error Reporting

and should rarely launch command interpreters.

The relationship itself became the detection.

### Key Takeaway

Understanding process lineage is fundamental to effective threat hunting. Abnormal parent-child relationships frequently provide stronger indicators of malicious execution than analyzing individual processes in isolation.

### Practical Detection Rule

Monitor abnormal parent-child relationships, including:

- WerFault.exe → cmd.exe
- Office applications → PowerShell
- Office applications → rundll32.exe
- Outlook.exe → cmd.exe
- Web browsers → PowerShell

## Lesson 7: Event Correlation Is More Valuable Than Individual Events

No single event provided sufficient evidence to explain the full attack sequence. Instead, the investigation required correlation between multiple Windows and Sysmon events, including Event IDs 1, 7, 8, 10, and 4624, to reconstruct the complete attack timeline.

### Example Investigation Timeline

During the credential dumping investigation, ProcessHacker.exe accessed LSASS memory, after which Security logs were reviewed for evidence of credential abuse. Although credential dumping activity was confirmed, no malicious authentication events were identified. This demonstrated that correlating multiple event sources provides significantly greater investigative value than analyzing individual events in isolation.

## Lesson 8: Sysmon Is One of the Most Valuable Defensive Data Sources

Across all investigations, Sysmon consistently provided the telemetry required to identify process creation, image loading, process injection, process access, credential dumping, and execution chains. Without Sysmon, several stages of the attack would have been significantly more difficult to detect and reconstruct.

### Key Takeaway

Properly configured Sysmon deployments significantly improve endpoint visibility by providing detailed telemetry required to detect, investigate, and reconstruct complex attack activity.

## Lesson 9: Threat Hunting Requires Hypothesis-Driven Analysis

Every investigation followed a similar methodology:

| Investigation Phase | Description |
|---------------------|-------------|
| Hypothesis | Define the suspected malicious activity. |
| Evidence Collection | Collect Windows Event Logs, Sysmon telemetry and Security logs. |
| Validation | Determine whether the collected evidence supports the hypothesis. |
| Conclusion | Confirm malicious activity or classify the event as a false positive. |

This hypothesis-driven methodology provides a structured approach for SOC analysts and DFIR practitioners when investigating Windows-based attacks.

## SOC Analyst Growth From This Module

After completing these investigations, an analyst should be able to:

•	Analyze Sysmon telemetry
•	Investigate DLL Hijacking activity
•	Detect CLR-based PowerShell execution
•	Identify process injection techniques
•	Investigate LSASS credential dumping
•	Review authentication activity following compromise
•	Detect suspicious parent-child process relationships
•	Build attack timelines from event logs
•	Create IOC-based detections
•	Develop Sigma and SIEM detection logic

## Final Reflection

The most important lesson from this module is that attackers rarely leave only one indicator behind.

A successful investigation comes from combining:

•	Process Creation
•	Module Loads
•	Memory Access
•	Authentication Events
•	Parent-Child Relationships

into a coherent timeline.

The analyst who understands how these pieces connect will consistently outperform one who focuses only on individual alerts or signatures.

This module demonstrates that effective threat hunting is ultimately the art of turning isolated events into a complete attack narrative.

## Core Lessons

- Legitimate processes can be abused by attackers.
- Behavioral telemetry is more valuable than process names.
- Event correlation provides stronger detections than individual events.
- Sysmon significantly improves Windows visibility.
- Effective threat hunting relies on hypothesis-driven investigations.
