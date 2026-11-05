# 03 - LSASS Dump and Login Review

## Executive Summary 

This investigation focuses on detecting credential dumping activity against the Local Security Authority Subsystem Service (LSASS) process and determining whether the stolen credentials were subsequently used for malicious authentication activity.

The provided evidence was located in:

C:\Logs\Dump

Analysis of Sysmon Process Access events revealed that:

•	ProcessHacker.exe accessed lsass.exe
•	The process requested extremely high privileges (0x1FFFFF)
•	The activity is consistent with credential dumping
•	The dump occurred before subsequent authentication activity

A secondary review of Windows Security logs was then performed to determine whether an attacker successfully used the harvested credentials.

The review found:

•	No suspicious logons occurred after the dump
•	Only legitimate service authentication activity was observed
•	No evidence of credential reuse was identified

## Investigation Objectives 

The goals of this investigation were:

•	Identify the process responsible for the LSASS dump
•	Understand how credential dumping appears in Sysmon
•	Analyze Process Access events
•	Determine whether harvested credentials were abused
•	Review successful logon events
•	Differentiate legitimate from malicious authentication activity
•	Reconstruct the attack timeline
•	Identify detection opportunities
•	Map activity to MITRE ATT&CK

## Background

### What Is LSASS?

LSASS (Local Security Authority Subsystem Service) is a core Windows process responsible for authentication, credential management, Kerberos ticket handling and enforcement of local security policy. Because sensitive credential material resides in LSASS memory, the process is a common target during post-exploitation.

### Why Attackers Target LSASS? 

LSASS contains valuable credential material in memory. LSASS memory may contain NTLM hashes, Kerberos tickets, cached credentials and other authentication secrets. Successful access to this process may allow an attacker to authenticate without knowledge of the original password.

### Credential Dumping

Credential dumping is a common post-compromise technique in which an attacker accesses LSASS memory to extract credential material. Common tooling includes Mimikatz, ProcDump, Process Hacker and abuse of comsvcs.dll.

## MITRE ATT&CK Mapping

Credential Dumping:

T1003.001
OS Credential Dumping: LSASS Memory


## Investigation Scenario

### Investigation Scope

The investigation focused on answering two primary questions:

•	Which process accessed LSASS memory? 
•	Was there evidence that harvested credentials were subsequently used for authentication?

## Data Sources

Primary sources:

C:\Logs\Dump\LsassDump.evtx
C:\Logs\Dump\SecurityLogs.evtx

Relevant Event IDs:

| Event ID | Source | Purpose |
|----------|--------|---------|
| 10 | Sysmon | Process Access |
| 4624 | Windows Security | Successful Logon |

## Phase 1 – Identifying the LSASS Dump

### Why Use Event ID 10?

Sysmon Event ID 10 records:

Process Access

This event appears when one process opens another process.

For credential dumping, attackers typically access:

lsass.exe

with elevated permissions.

### Initial Investigation

PowerShell command:

```powershell
Get-WinEvent -FilterHashtable @{
Path='C:\Logs\Dump\LsassDump.evtx'
ID=10
} |
Where-Object {$_.Properties[8].Value -like "*lsass*"} |
Format-List
``` 

### Understanding the Query

The query filters Sysmon Process Access (Event ID 10) events targeting lsass.exe, then expands the complete event record for detailed review.

## Investigation Findings

The results revealed:

SourceImage:
C:\Program Files\Process Hacker 2\ProcessHacker.exe

and

TargetImage:
C:\Windows\System32\lsass.exe

### Event Interpretation

The SourceImage field identifies the process requesting access, while TargetImage identifies the process being accessed.

In this investigation:

•	SourceImage = ProcessHacker.exe 
•	TargetImage = lsass.exe 

This combination strongly indicates credential dumping behaviour.

### Why This Matters

The event tells us:

ProcessHacker.exe
        ↓
Accessed
        ↓
lsass.exe

This behavior is strongly associated with credential dumping.

### Additional Evidence

The event also showed:

GrantedAccess: 0x1FFFFF

### Understanding GrantedAccess

The observed access mask (0x1FFFFF) represents nearly unrestricted access to the target process, including permissions required to inspect and manipulate process memory. Such access is commonly associated with credential dumping tools.

### Why 0x1FFFFF Is Suspicious

Full access allows:

•	Memory reading
•	Memory writing
•	Handle duplication
•	Process manipulation

These permissions are commonly required for:

Credential Dumping

## Attack Reconstruction

The attack chain becomes:

ProcessHacker.exe
          ↓
Opens lsass.exe
          ↓
Obtains Full Access
          ↓
Reads Process Memory
          ↓
Credentials Extracted

## Determining the Answer

The question asks:

Which process performed the LSASS dump?

The responsible process is:

ProcessHacker.exe

## Screenshots 

### Figure 1. Opening LsassDump.evtx in Event Viewer for credential dumping analysis.

Opening LsassDump.evtx.

[INSERT SCREENSHOT]

### Figure 2. PowerShell query filtering Sysmon Event ID 10 (Process Access) events targeting lsass.exe.

PowerShell query filtering Event ID 10.

[INSERT SCREENSHOT]

### Figure 3. Event details identifying ProcessHacker.exe as the process accessing LSASS memory.

SourceImage = ProcessHacker.exe.

[INSERT SCREENSHOT]

### Figure 4. Event details confirming lsass.exe as the target process.

TargetImage = lsass.exe.

[INSERT SCREENSHOT]

### Figure 5. GrantedAccess value of 0x1FFFFF indicating full access permissions to LSASS memory. 

GrantedAccess = 0x1FFFFF.

[INSERT SCREENSHOT]

## Phase 2 – Reviewing Authentication Activity

After identifying the dump, the next question becomes:

Did the attacker use the stolen credentials?

### Why This Matters

A credential dump alone does not prove compromise.

The attacker must actually use the credentials.

Typical follow-up activity includes:

Pass-the-Hash
RDP Login
Network Logon
Remote Administration
Lateral Movement

### Reviewing Security Logs

Open:

C:\Logs\Dump\SecurityLogs.evtx

### Filtering Successful Logons

Event ID:

4624

represents:

An account was successfully logged on

### Event Viewer Procedure

1.	Open SecurityLogs.evtx
2.	Select:
Filter Current Log
3.	Enter:
4624
4.	Review all successful logons occurring after the dump.

### What We Expect to See

Successful authentication events occurring after the credential dump were reviewed for evidence of credential reuse, remote logons or administrative access.

## Investigation Findings

One of the observed events contained:

TargetUserName: SYSTEM

Additional details:

LogonType: 5
ProcessName:
C:\Windows\System32\services.exe
IpAddress: -

## Understanding Logon Type 5

Logon Type 5 represents a Windows Service Logon. Windows services authenticate using service accounts as part of normal operating system behavior.

Observed Event

- Logon Type: 5
- TargetUserName: SYSTEM
- ProcessName: C:\Windows\System32\services.exe

This represents a standard Windows Service Logon and is not indicative of attacker activity.

### Why This Is Not Suspicious

Observed:

SYSTEM Account

Observed:

services.exe

Observed:

No IP Address

Observed:

Logon Type 5

None of these indicate attacker activity.

## Timeline Reconstruction

### Stage 1

Credential Dump:

ProcessHacker.exe
        ↓
LSASS Access

### Stage 2

Credential Review:

Attacker Obtains Credentials

### Stage 3

Security Log Review:

4624 Events

### Stage 4

Authentication Analysis:

Only Service Logons Found

SYSTEM
LogonType 5
services.exe

### Stage 5

Conclusion:

No Malicious Login Detected

### Detection Opportunities

#### Sysmon Event ID 10

Alert when:

TargetImage = lsass.exe

#### High Granted Access

Alert on:

0x1FFFFF

#### Known Dumping Tools

Alert when:

ProcessHacker.exe
Mimikatz.exe
procdump.exe

access:

lsass.exe

#### Post-Dump Monitoring

After any LSASS access event:

Monitor:

4624
4625
4648
4672

for credential abuse.

## MITRE ATT&CK Mapping

| MITRE ATT&CK Technique | Technique ID | Investigation Relevance |
|-------------------------|--------------|--------------------------|
| OS Credential Dumping: LSASS Memory | T1003.001 | Credential dumping from LSASS memory |
| Valid Accounts | T1078 | Potential use of harvested credentials |
| Pass the Hash | T1550.002 | Possible follow-on activity after credential theft |

## Key Findings

•	LSASS access was identified.
•	ProcessHacker.exe accessed lsass.exe.
•	Full process permissions were granted.
•	Activity is consistent with credential dumping.
•	Security logs were reviewed.
•	No suspicious authentication followed the dump.
•	No evidence of credential abuse was found.

## Conclusion

This investigation demonstrates how Sysmon and Windows Security logs complement each other during incident response.

Sysmon Event ID 10 provided evidence of credential dumping activity by ProcessHacker.exe against LSASS, while Security Event ID 4624 allowed verification of post-compromise authentication behavior.

Although credential dumping occurred, no evidence was found that the harvested credentials were subsequently used for malicious authentication activity. The observed logons were legitimate Windows service logons and did not indicate attacker access.

This workflow reflects a common SOC investigation pattern: identify credential theft, then immediately determine whether those credentials were successfully weaponized.
