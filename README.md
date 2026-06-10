# Rocky Clinic OpenEMR Threat Hunt

## Overview

This project documents a threat hunting investigation conducted in Microsoft Sentinel involving a compromised OpenEMR environment hosted on Rocky Linux and running within Docker containers.

The objective was to reconstruct the attack lifecycle by analyzing authentication events, process telemetry, system activity, and operator behavior. The investigation focused on identifying how the attacker gained access, performed discovery, escalated privileges, established persistence, and operated within the environment while avoiding detection.

## Environment

- **Platform:** OpenEMR
- **Operating System:** Rocky Linux
- **Container Runtime:** Docker
- **SIEM:** Microsoft Sentinel
- **Investigation Window:** February 4–14, 2026

## Skills Demonstrated

- Threat Hunting
- Microsoft Sentinel
- Kusto Query Language (KQL)
- Linux Security Monitoring
- Incident Response
- Log Analysis
- Process Telemetry Investigation
- Attack Timeline Reconstruction
- MITRE ATT&CK Mapping

## Investigation Highlights

- Identified suspicious remote access activity originating from external IP addresses.
- Reconstructed attacker sessions using process telemetry and authentication events.
- Distinguished operator-driven actions from automated system processes.
- Identified host and operating system fingerprinting activity.
- Tracked privilege enumeration and escalation attempts.
- Investigated Docker-based administrative activity and trust boundary crossings.
- Built an attack timeline from initial access through post-compromise actions.

## Key Takeaways

This investigation emphasized the importance of session reconstruction, timeline analysis, and behavioral hunting techniques. Rather than relying on alerts, the investigation focused on understanding attacker intent through process execution, authentication patterns, and interactive command activity.

The exercise reinforced practical incident response workflows and demonstrated how Microsoft Sentinel can be used to reconstruct complex attack chains from endpoint telemetry.

## Tools Used

- Microsoft Sentinel
- Kusto Query Language (KQL)
- Linux Command-Line Analysis
- MITRE ATT&CK Framework

## Repository Contents

```text
.
├── README.md
├── kql/
├── screenshots/
├── findings/
├── timeline/
└── investigation-notes/
```

## MITRE ATT&CK Techniques Observed

| Technique | ATT&CK ID |
|------------|------------|
| System Owner/User Discovery | T1033 |
| Account Discovery | T1087 |
| Permission Groups Discovery | T1069 |
| Command and Scripting Interpreter | T1059 |
| Valid Accounts | T1078 |
| Container and Virtualization Discovery | T1613 |

## Disclaimer

This repository contains investigative findings, methodology, and KQL queries used during the hunt. Challenge answers have been intentionally omitted to preserve the integrity of the exercise.
