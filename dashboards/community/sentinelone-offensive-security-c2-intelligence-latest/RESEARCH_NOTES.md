# Offensive Security & C2 Activity Intelligence — RedEye-Inspired SOC View

This dashboard creates a **SentinelOne-native investigation workspace for hacking tools, post-exploitation utilities, C2 frameworks, tunneling tools, and offensive operator activity**.

It is inspired by the investigative concepts used by **CISA / PNNL RedEye**: campaign review, hosts, beacons, commands, command types, timelines, attack-path visualization, and raw evidence exploration. The dashboard does **not** import RedEye code or require RedEye.

## RedEye concept → SentinelOne equivalent

| RedEye concept | SentinelOne implementation |
|---|---|
| Campaign | Selected dashboard time range + Site / Endpoint filters |
| Host | `endpoint.name` |
| Beacon | C2-related process / Storyline + its IP Connect telemetry |
| Command | `tgt.process.cmdline`, process creation, and child execution |
| Command Type | Offensive tool category / process name |
| Teamserver | Remote destination IP/country contacted by tracked C2/tunneling processes |
| Operator | **Not directly observable from endpoint telemetry**; closest context is `src.process.user` / endpoint security context |
| Attack graph | Sankey pivots across endpoint → launcher → tool → remote infrastructure |
| Timeline | `timebucket()` process and network activity |
| Raw logs | Investigation tables with process, hash, path, command line, Storyline, IP, port, and protocol |

## Scope

The catalog is seeded from NeverOff's SentinelOne Application Control hardening content and expanded for this dashboard. It covers:

- C2 frameworks / agents: Cobalt Strike, Brute Ratel C4, Sliver, Havoc, Empire/Starkiller, Covenant, Metasploit/Meterpreter, PoshC2, Merlin, SharpC2, SILENTTRINITY, Koadic, Villain, Mythic, AdaptixC2.
- C2 tunneling / proxy infrastructure: Chisel, Ligolo, FRP, Gost, IOX, Ngrok, Ncat, Plink, Stunnel, Socat, Wstunnel, Rathole, Bore, Cloudflared, Proxychains, Proxytunnel, Tun2Socks.
- Credential Access.
- Privilege Escalation.
- Lateral Movement / Remote Execution.
- Defense Evasion / Payload Generation.
- Exploitation / Pentesting.
- Reconnaissance / Discovery.
- Ransomware operator tooling.

**Tracked exact offensive process names:** 357  
**Tracked exact C2 process names:** 48  
**C2 framework families:** 15

## Signal model

### Exact process-name catalog
Highest fidelity for known tool names, but attackers can rename binaries.

### C2 keyword / artifact matching
The C2 Frameworks tab also searches process image paths and command lines for framework-specific strings. This improves coverage for renamed controllers, loaders, or packaged tooling, but can create false positives.

### Storyline correlation
Process creation is analyzed as:
`src.process` → launcher / parent  
`tgt.process` → executed child / offensive tool

`tgt.process.storyline.id` is retained wherever possible so the analyst can pivot into the broader SentinelOne Storyline.

### Network / beacon context
For `IP Connect` telemetry, the dashboard attributes network activity to `src.process` and pivots:
`Endpoint → C2/Tunnel Process → Destination Country → Remote IP`

A high connection count is **not automatically beaconing**. Use timing, destination stability, command line, Storyline context, and threat intelligence to determine whether activity represents actual C2.

## Custom triage model

This dashboard uses an analytic priority model for SOC review. It is **not a native SentinelOne severity**.

- **100 / CRITICAL** — C2 Framework / Agent
- **90 / CRITICAL** — Credential Access, Privilege Escalation, Ransomware Operator Tool
- **85 / HIGH** — Lateral Movement
- **80 / HIGH** — Defense Evasion / Payload, C2 Tunneling / Proxy
- **70 / HIGH** — Exploitation / Pentesting
- **50 / ELEVATED** — Reconnaissance / Discovery

## Interpretation limitations

- A tool name alone does not prove malicious intent; authorized Red Team, vulnerability-management, DFIR, admin, or development activity may be legitimate.
- Many offensive frameworks rename, inject, reflectively load, sideload, or execute through legitimate interpreters. Exact-name matching therefore cannot provide complete C2 detection.
- RedEye can parse native C2 logs and expose actual operators, beacons, commands, and teamserver metadata. SentinelOne endpoint telemetry cannot reconstruct C2-operator identity unless those native C2 logs are separately ingested into the Data Lake.
- MITRE labels shown here are **triage-oriented mappings by tool class**, not authoritative per-event ATT&CK attribution.
- Treat the dashboard as an investigation and hunting plane. Convert validated high-signal behaviors into Star Custom Rules / correlation rules where real-time alerting is required.

Developed by the Threat Detection Engineering Division at NeverOff Technology (SentinelOne Division)
Dominican Republic
