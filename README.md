# Windows Endpoint Threat Detection and Analysis
| Hack-the-Box Academy |

A hands-on SOC investigation project focused on detecting and analyzing Windows-based attacker techniques using **Sysmon**, **Windows Event Logs**, **PowerShell**, **Event Viewer**, and **MITRE ATT&CK**.

The project demonstrates how Windows event telemetry can be leveraged to investigate common post-exploitation techniques, reconstruct attack chains, identify Indicators of Compromise (IOCs), and translate investigative findings into reusable detection logic for Security Operations Centers (SOCs).

---

## Project Objectives

The primary objectives of this project are to:

- Investigate Windows attack techniques using native Windows logs and Sysmon telemetry.
- Develop practical threat hunting methodologies based on Windows Event Logs.
- Reconstruct attacker activity through event correlation and process analysis.
- Identify Indicators of Compromise (IOCs) and behavioral detection opportunities.
- Map observed techniques to the MITRE ATT&CK framework.
- Produce reusable detection logic suitable for SIEM platforms and SOC operations.

---

## Topics Covered

This project investigates the following Windows attack techniques:

- DLL Hijacking
- Unmanaged PowerShell Execution
- Process Injection
- LSASS Credential Dumping
- Post-Compromise Authentication Analysis
- Suspicious Parent-Child Process Relationships

---

# Investigation Workflow

Each investigation follows a structured methodology based on SOC investigation and Digital Forensics and Incident Response (DFIR) principles.

1. Review available telemetry.
2. Identify suspicious activity.
3. Validate findings using multiple evidence sources.
4. Reconstruct the attack sequence.
5. Identify Indicators of Compromise (IOCs).
6. Develop detection opportunities.
7. Map activity to MITRE ATT&CK.

---

# Project Sections

## 1. DLL Hijacking

Investigates DLL Search Order Hijacking through Sysmon Image Load (Event ID 7).

Topics include:

- Image Load analysis
- Unsigned DLL detection
- Event Viewer validation
- PowerShell hunting
- DLL search order abuse
- Detection opportunities
- MITRE ATT&CK mapping

---

## 2. Unmanaged PowerShell and Injection

Investigates potential unmanaged PowerShell execution and process injection by analyzing unexpected CLR module loading and remote thread creation.

The investigation identified Calculator.exe loading clr.dll and rundll32.exe creating a remote thread within Calculator.exe. These observations were consistent with potential in-process execution and injection activity, although actual PowerShell command execution was not independently confirmed.

Topics include:

- CLR module loading
- PowerShell hosting
- Process Injection
- CreateRemoteThread analysis
- Event ID 7
- Event ID 8
- Detection opportunities
- MITRE ATT&CK mapping

---

## 3. LSASS Dump and Login Review

Investigates suspicious LSASS memory access associated with potential credential dumping and examines subsequent authentication events for evidence of credential misuse.

Topics include:

- Process Access (Event ID 10)
- LSASS memory analysis
- GrantedAccess analysis
- Successful logon review
- Windows Security logs
- Detection opportunities
- MITRE ATT&CK mapping

---

## 4. Strange Parent-Child Relationship

Investigates abnormal process creation activity through parent-child process analysis.

Topics include:

- Process Creation (Event ID 1)
- Parent-child relationships
- Process lineage reconstruction
- WerFault.exe analysis
- Command execution analysis
- Detection opportunities
- MITRE ATT&CK mapping

---

## 5. Detection Logic and IOCs

Consolidates reusable detection content extracted from every investigation.

Includes:

- Detection logic
- PowerShell hunting queries
- Sigma detection concepts
- IOC lists
- Event ID references
- SOC detection recommendations

The detection concepts are intended for educational analysis and require validation and environment-specific tuning before production deployment.

---

## 6. Lessons Learned

Summarizes the key defensive insights obtained throughout the investigations.

Topics include:

- Behavioral detection
- Event correlation
- Threat hunting methodology
- Sysmon visibility
- Detection engineering principles
- SOC investigation best practices

---

# Data Sources

The investigations primarily rely on:

- Sysmon Operational Logs
- Windows Security Event Logs
- Event Viewer (.evtx)
- PowerShell Get-WinEvent
- Windows Process Telemetry

---

# MITRE ATT&CK Coverage

The investigations cover techniques including:

| Technique | ATT&CK ID | Evidence Assessment |
|-----------|-----------|-----------|
| DLL Search Order Hijacking | T1574.001 | Consistent with observed suspicious DLL loading |
| PowerShell | T1059.001 | Suspected: execution unconfirmed |
| Process Injection | T1055 | Remote thread creation observed: injection payload unconfirmed |
| OS Credential Dumping: LSASS Memory | T1003.001 | Suspicious LSASS access observed: credential extraction unconfirmed |
| Windows Command Shell | T1059.003 | Command execution recorded  |
| System Owner/User Discovery | T1033 | 'whoami' command execution recorded |

**ATT&CK Mapping Note**: Valid Accounts (T1078) is excluded because the investigation did not identify malicious credential reuse. Process Discovery (T1057) is also excluded because the documented **whoami** command supports System Owner/User Discovery (T1033), rather than process enumeration.

The ATT&CK mappings distinguish directly observed behavior from suspected techniques. Where the available telemetry does not conclusively establish malicious execution or successful exploitation, the corresponding technique is treated as an investigative hypothesis rather than a confirmed finding.

---

# Skills Demonstrated

Through this project, the following SOC analyst skills are demonstrated:

- Windows Event Log analysis
- Sysmon investigation
- PowerShell threat hunting
- Event correlation
- Process behavior analysis
- Parent-child process analysis
- DLL Hijacking investigation and detection
- Investigation of potential unmanaged PowerShell execution
- Process Injection indicator analysis
- LSASS credential dumping investigation
- Authentication log analysis
- IOC development
- Sigma rule development
- Detection engineering
- MITRE ATT&CK mapping
- Threat hunting methodology

These skills were developed through practical investigation of controlled laboratory scenarios, with an emphasis on evidence analysis, behavioral detection, and structured SOC reporting.

---

# Tools Used

- Windows Event Viewer
- PowerShell
- Sysmon
- Windows Security Auditing
- MITRE ATT&CK
- Sigma

---

# Key Takeaways

The investigations reinforce several important defensive principles:

- Legitimate processes can be abused by attackers.
- Behavioral analysis is more reliable than relying solely on process names.
- Event correlation provides significantly stronger visibility than individual log analysis.
- Properly configured Sysmon deployments greatly improve Windows detection capabilities.
- Effective threat hunting requires a structured, hypothesis-driven investigative methodology.

- Suspicious telemetry should be distinguished from confirmed malicious activity to ensure accurate investigation findings and reduce false positives.

---
