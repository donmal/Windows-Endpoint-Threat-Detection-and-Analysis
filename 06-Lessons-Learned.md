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

### Investigation Context

At first glance, the process involved in the DLL hijacking investigation appeared completely legitimate:

Dism.exe

Because DISM is a legitimate Microsoft utility, many analysts could mistakenly assume the activity is benign.

### Investigation Findings

The executable loaded:

DismCore.dll

from an unexpected location.

More importantly:

Signed = False

revealed that the DLL was not digitally signed.

The combination of an unexpected DLL location and an unsigned module raised suspicion of DLL hijacking and warranted further investigation.

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

**Detection Consideration**: An unsigned DLL is not automatically malicious. Analysts should correlate module signatures, loading paths, process behavior, and additional telemetry before confirming DLL hijacking.

## Lesson 2: PowerShell Does Not Need powershell.exe

### Detection Challenge

A common assumption is that PowerShell activity is always associated with powershell.exe.

### Investigation Findings

The investigation revealed:

Calculator.exe

loading:

clr.dll

and hosting PowerShell internally.

No visible PowerShell process was required.

### Why This Matters

Attackers frequently use:

- PowerShell Hosting

- PowerShell Runspaces

- Reflective Loading

- In-Memory Execution

to avoid traditional detections.

This technique is commonly referred to as:

Unmanaged PowerShell

or

PowerShell Without PowerShell.exe

### Key Takeaway

Detection strategies should prioritize behavioral indicators rather than relying solely on process names. Monitoring CLR libraries loaded by unexpected processes provides additional detection opportunities than searching exclusively for powershell.exe.

### Practical Detection Rule

Investigate unexpected processes loading the following modules, particularly when multiple indicators occur within the same execution chain:

- clr.dll
  
- clrjit.dll
  
- System.Management.Automation.dll

Particular attention should be given to Office applications, web browsers, utilities, and other processes not typically associated with PowerShell execution.

**Detection Consideration**: CLR initialization alone does not establish malicious PowerShell execution. Correlation with PowerShell-related assemblies, process ancestry, and execution telemetry is necessary to improve detection confidence.

## Lesson 3: Process Injection Leaves Traces

### Detection Challenge

A common assumption is that process injection completely conceals malicious execution by running code inside legitimate processes.

### Investigation Findings

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

**Detection Consideration**: CreateRemoteThread activity is a useful injection indicator but is not independently conclusive. Analysts should correlate source-target relationships, process access, and subsequent execution behavior.

## Lesson 4: Credential Dumping Is Usually Observable

### Detection Challenge

A common assumption is that credential dumping can be performed without generating observable forensic evidence.

### Investigation Findings

The investigation identified ProcessHacker.exe accessing lsass.exe with a GrantedAccess value of 0x1FFFFF, indicating extensive permissions to read process memory. This level of access is commonly associated with credential dumping activity.

### Why This Matters

Many credential theft tools require:

•	Reading LSASS memory

•	Opening privileged handles

•	Extracting sensitive authentication material

These actions may generate detectable events when appropriate endpoint telemetry is enabled..

### Key Takeaway

Suspicious LSASS memory access can provide valuable evidence of potential credential dumping, even when subsequent credential abuse is not observed.

### Practical Detection Rule

Investigate LSASS access involving:

- TargetImage = lsass.exe
  
- High GrantedAccess values
  
- Unknown or untrusted processes
  
- Administrative utilities performing memory access

**Detection Consideration**: Extensive LSASS access permissions indicate potential credential theft but do not independently confirm successful credential extraction.

## Lesson 5: Not Every Login After an Attack Is Malicious

### Investigation Context

A common assumption is that any successful logon occurring after credential dumping indicates credential abuse.

### Investigation Findings

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

**Investigation Outcome**: The observed SYSTEM service logon did not provide evidence of malicious credential use. This reinforced the importance of validating authentication context before escalating an alert.

## Lesson 6: Parent-Child Relationships Reveal Execution Chains

### Investigation Context

A process may appear legitimate when viewed in isolation without considering its parent-child execution context.

### Investigation Findings 

The investigation identified WerFault.exe spawning cmd.exe, which subsequently executed the command `cmd.exe /c whoami`. This abnormal parent-child relationship revealed temporary command execution initiated through an unexpected Windows process.

### Why This Matters

WerFault is normally used for:

Windows Error Reporting

and should rarely launch command interpreters.

The unexpected parent-child relationship provided a valuable detection signal, particularly when combined with the observed command-line activity.

### Key Takeaway

Understanding process lineage is fundamental to effective threat hunting. Abnormal parent-child relationships frequently provide stronger indicators of malicious execution than analyzing individual processes in isolation.

### Practical Detection Rule

Monitor abnormal parent-child relationships, including:

- WerFault.exe → cmd.exe
  
- Office applications → PowerShell
  
- Office applications → rundll32.exe
  
- Outlook.exe → cmd.exe
  
- Web browsers → PowerShell

**Detection Consideration**: The WerFault.exe → cmd.exe relationship was observed during this investigation. The remaining combinations represent additional hunting opportunities rather than confirmed findings from the analyzed logs.

## Lesson 7: Event Correlation Is More Valuable Than Individual Events

Individual events provided valuable evidence, but understanding the broader attack scenarios required correlating multiple telemetry sources.

Instead, the investigation required correlation between multiple Windows and Sysmon events, including Event IDs 1, 7, 8, 10, and 4624, to reconstruct the relevant execution and investigation timelines.

### Example Investigation Timeline

During the credential dumping investigation, ProcessHacker.exe accessed LSASS memory, after which Security logs were reviewed for evidence of credential abuse. Although suspicious LSASS access consistent with potential credential dumping was identified, no malicious authentication events were identified.

This demonstrated that correlating multiple event sources provides significantly greater investigative value than analyzing individual events in isolation.

## Lesson 8: Sysmon Is One of the Most Valuable Defensive Data Sources

Across all investigations, Sysmon consistently provided the telemetry required to identify process creation, image loading, process injection, process access, potential credential dumping activity, and execution chains. 

Without Sysmon, several stages of the attack would have been significantly more difficult to detect and reconstruct.

### Key Takeaway

Properly configured Sysmon deployments significantly improve endpoint visibility by providing detailed telemetry required to detect, investigate, and reconstruct complex attack activity.

Sysmon telemetry should be correlated with Windows Security logs and other available endpoint data sources to provide a more complete investigative picture.

## Lesson 9: Threat Hunting Requires Hypothesis-Driven Analysis

Every investigation followed a similar methodology:

| Investigation Phase | Description |
|---------------------|-------------|
| Hypothesis | Define the suspected malicious activity. |
| Evidence Collection | Collect Windows Event Logs, Sysmon telemetry and Security logs. |
| Validation | Determine whether the collected evidence supports the hypothesis. |
| Conclusion | Classify the activity as malicious, benign, or inconclusive based on the available evidence. |

This hypothesis-driven methodology provides a structured approach for SOC analysts and DFIR practitioners when investigating Windows-based attacks.

## Technical Skills Demonstrated 

The investigations provided hands-on practice in the following SOC analysis and detection engineering activities:

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

These activities strengthened practical skills in endpoint telemetry analysis, behavioral detection, investigation methodology, and evidence-based reporting.

## Final Reflection

The most important lesson from this module is that attackers rarely leave only one indicator behind.

A successful investigation comes from combining:

•	Process Creation

•	Module Loads

•	Memory Access

•	Authentication Events

•	Parent-Child Relationships

into a coherent timeline.

Correlating these artifacts enables analysts to develop a more reliable understanding of suspicious activity than relying exclusively on isolated alerts or signatures.

These investigations demonstrated how individual Windows and Sysmon events can be transformed into actionable findings through structured analysis, behavioral correlation, and careful validation of evidence.

## Core Lessons

- Legitimate processes can be abused by attackers.
  
- Behavioral telemetry is more valuable than process names.
  
- Event correlation provides stronger detections than individual events.
  
- Sysmon significantly improves Windows visibility.
  
- Effective threat hunting relies on hypothesis-driven investigations.
