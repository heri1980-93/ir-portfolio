Simulated DFIR Write-up — PowerShell-based Downloader (One-page)

Overview
A simulated incident where a user account executed a suspicious PowerShell command that fetched and executed a payload. Objective: demonstrate DFIR methodology (detection, collection, analysis, containment, remediation).

Scope
- A single Windows host in a lab environment
- Evidence types collected: Event Logs (Security, System, Application), PowerShell transcripts, memory dump, disk image of user directory, network logs

Timeline & Key Findings
1. T0: 2025-09-15 14:02 — Suspicious process creation recorded (EventCode 4688) showing PowerShell.exe child of explorer.exe with long base64-looking argument.
2. T0+1: 2025-09-15 14:03 — PowerShell initiated an outbound HTTP request to hxxp://malicious.example.com/payload.exe (recorded in firewall/proxy logs).
3. T0+2: 2025-09-15 14:05 — Process spawned a child named evilpayload.exe and wrote it to C:\Users\victim\AppData\Local\Temp\evilpayload.exe.
4. T0+3: Memory capture showed injected code patterns consistent with known loader behavior; YARA rule Suspicious_PowerShell_And_Payload matched the memory snapshot.

Investigation Steps
- Triage: Identified affected host and user from Splunk alert (anomalous auth and process creation). Retrieved Windows Event Logs and process creation events.
- Collection: Acquired volatile memory using a memory acquisition tool (e.g., DumpIt) and captured relevant disk artifacts (temp folder, prefetch, registry hives).
- Analysis: Used Volatility to extract running process list, command line args, and network connections from memory. Correlated process creation events (4688) with firewall logs and Splunk searches.
- Detection: Splunk search 'Detect_Lateral_Movement.savedsearch' surfaced abnormal counts for the user across multiple hosts; YARA rule matched base64-like strings and suspicious filename.

Indicators of Compromise (IOC)
- Command-line pattern: powershell -EncodedCommand <long base64 string>
- Filename: C:\Users\victim\AppData\Local\Temp\evilpayload.exe
- Network: hxxp://malicious.example.com/payload.exe

Containment & Remediation
- Isolate host from network immediately via EDR or network ACLs.
- Collect full forensic image and memory before attempting remediation.
- Reset credentials for the impacted account and force MFA re-enrollment.
- Remove persistence (scheduled tasks, registry run keys, services) and block payload URL at perimeter.
- Re-image host if root cause indicates deep compromise.

Lessons & Tuning
- Add a scheduled Splunk search for PowerShell EncodedCommand patterns and long base64-like strings; pipe matches into an analyst triage queue.
- Tune EDR to flag new child processes launched from explorer.exe that write executables to user Temp directories.
- Implement PowerShell logging (ScriptBlockLogging) and centralize PowerShell logs to the SIEM to increase visibility.

Artifacts referenced
- yara/my_suspicious_rule.yar
- splunk/detect_lateral_movement.savedsearch

Author
Heriberto Hernandez Garduno — herib26@gmail.com
