# Authentication Threat Intelligence — Failed Login Operations | V1

**Mission:** transform SentinelOne `Login` telemetry into a SOC-focused authentication defense view for failed logins, brute-force triage, password-spraying discovery, privileged-account review, source/endpoint attribution, and investigation.

## Core telemetry
The dashboard is anchored on:

`event.type == "Login" AND event.login.loginIsSuccessful == false`

The supplied source dashboard confirms:
- `event.type`
- `event.login.loginIsSuccessful`
- `event.login.userName`

This V1 also uses common SentinelOne login-event context fields for deeper triage:
- `event.login.type`
- `event.login.isAdministratorEquivalent`
- `src.endpoint.ip.address`
- `endpoint.name`
- `site.name`
- `agent.uuid`

Validate field population in the target tenant before production rollout because login telemetry can vary by OS, agent/data-source coverage, and event source.

## SOC operating model
Use the dashboard to answer:
1. **How much failed authentication activity is occurring?**
2. **Which accounts are being targeted most heavily?**
3. **Which endpoints receive the failures?**
4. **Which source IPs are generating the activity?**
5. **Are privileged / administrator-equivalent identities involved?**
6. **Does one source target many accounts (password spraying)?**
7. **Does one account receive many failures (password guessing / brute force)?**
8. **Do the same user + source + endpoint tuples show both failures and successful logins in the selected range?**
9. **What raw events should the analyst pivot into immediately?**

## Custom triage heuristics
These are **NeverOff analytic heuristics**, not SentinelOne threat scores or native severity values:
- **Brute-force candidate:** ≥ 10 failed logins against one account in the selected range.
- **Password-spray candidate:** ≥ 10 failed logins from one source IP and ≥ 5 distinct target accounts.
- **Burst cluster:** ≥ 5 failures for the same source IP + account + endpoint inside a 15-minute bucket.
- **Distributed targeting:** ≥ 10 failures against one account from ≥ 3 distinct source IPs.
- **Privileged attention:** any failure where `event.login.isAdministratorEquivalent == true`.

Tune thresholds to the client's authentication baseline, identity architecture, lockout policy, remote-access model, and service-account behavior.

## MITRE ATT&CK alignment
Primary analytic alignment:
- **T1110 — Brute Force**
- **T1110.001 — Password Guessing**
- **T1110.003 — Password Spraying**
- **T1078 — Valid Accounts** for successful-authentication follow-up and compromise validation

## Interpretation cautions
- Failed logins are not inherently malicious. They may result from expired passwords, stale services, mapped drives, scheduled tasks, disconnected VPN sessions, or user error.
- A source IP can be private, NATed, proxied, VPN-assigned, or otherwise non-geolocatable.
- The **Failure + Success Coexistence** views are range-level correlation aids. They do **not** prove that success occurred after the failures; confirm chronology in the raw events.
- Event counts represent observed login events, not unique human authentication sessions.

## Recommended SOC workflow
**Command Center → Spray & Brute Force → Privileged Access → Source & Endpoint → Investigation**

Use the **Investigation** tab as the evidence pivot and the **Detection Engineering** tab as the starting point for converting stable patterns into alerts / STAR or correlation logic.

Developed by the Threat Detection Engineering Division at NeverOff Technology (SentinelOne Division)
Dominican Republic

---

# Detection Engineering — Authentication Analytics

This tab documents the hunting logic used by the dashboard so stable patterns can be promoted into operational alerting.

## Base failed-login hunt
`| filter(event.type == "Login" AND event.login.loginIsSuccessful == false)`

## High-volume account / password guessing
`| filter(event.type == "Login" AND event.login.loginIsSuccessful == false AND !isempty(event.login.userName)) | group FailedLogins = count(), SourceIPs = estimate_distinct(src.endpoint.ip.address), Endpoints = estimate_distinct(endpoint.name) by event.login.userName | filter FailedLogins >= 10 | sort -FailedLogins`

**Use case:** repeated authentication failures against one account.  
**ATT&CK:** T1110 / T1110.001.

## Password-spray candidate
`| filter(event.type == "Login" AND event.login.loginIsSuccessful == false AND !isempty(src.endpoint.ip.address)) | group FailedLogins = count(), TargetUsers = estimate_distinct(event.login.userName), TargetEndpoints = estimate_distinct(endpoint.name) by src.endpoint.ip.address | filter FailedLogins >= 10 AND TargetUsers >= 5 | sort -TargetUsers, -FailedLogins`

**Use case:** one source IP testing credentials across many identities.  
**ATT&CK:** T1110.003.

## Privileged failed authentication
`| filter(event.type == "Login" AND event.login.loginIsSuccessful == false AND event.login.isAdministratorEquivalent == true)`

**Use case:** prioritize failed authentication involving administrator-equivalent context.

## 15-minute burst
`| filter(event.type == "Login" AND event.login.loginIsSuccessful == false AND !isempty(event.login.userName) AND !isempty(endpoint.name)) | group FailedLogins = count() by Bucket = timebucket('15 minutes'), src.endpoint.ip.address, event.login.userName, endpoint.name | filter FailedLogins >= 5 | sort -Bucket, -FailedLogins`

**Use case:** short, high-velocity password guessing.

## Failure + success coexistence
`| filter(event.type == "Login" AND !isempty(event.login.userName) AND !isempty(endpoint.name)) | let FailureFlag = event.login.loginIsSuccessful == false ? 1 : 0 | let SuccessFlag = event.login.loginIsSuccessful == true ? 1 : 0 | group FailedLogins = sum(FailureFlag), SuccessfulLogins = sum(SuccessFlag) by event.login.userName, src.endpoint.ip.address, endpoint.name | filter FailedLogins > 0 AND SuccessfulLogins > 0 | sort -FailedLogins`

**Use case:** triage accounts where failed and successful authentication appear in the same selected time range.  
**ATT&CK follow-up:** T1078.  
**Important:** confirm chronology in raw events before classifying as successful compromise.

## Production tuning recommendations
- Start with the dashboard heuristics as **visibility thresholds**, not automatic containment thresholds.
- Baseline service accounts, scheduled tasks, jump hosts, VPN concentrators, RMM tools, and identity infrastructure.
- Increase severity when failed-login bursts involve privileged identities, many endpoints, multiple source IPs, or a subsequent successful login.
- Exclude only well-understood, documented benign patterns.
- Convert validated use cases into alerting / correlation logic after observing production behavior.

