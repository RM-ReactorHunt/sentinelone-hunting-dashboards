# DNS Threat Intelligence, C2 & Anomaly Intelligence | NeverOff V1

**Mission:** turn SentinelOne DNS telemetry into an analyst-focused hunting plane for DNS-based command-and-control, domain-generation behavior, tunneling/exfiltration candidates, anomalous resolution patterns, abuse-prone infrastructure, Threat Intelligence hits, and endpoint/process attribution.

## Native telemetry used
The dashboard is centered on `event.category == "dns"` and uses fields confirmed in the current SentinelOne field catalog:

- `event.dns.request` — requested domain.
- `event.dns.response` — DNS response data.
- `event.dns.responseCode` — numeric DNS response code.
- `event.dns.protocol` — DNS protocol value.
- `event.dns.transportProtocol` — DNS transport protocol.
- `event.dns.provider` — telemetry provider.
- `src.process.dnsCount` — DNS request count associated with the source process.
- `endpoint.name`, `endpoint.os`, `site.name`, `src.process.name`, `src.process.user`.

The dashboard also uses common SentinelOne process context such as `src.process.cmdline`, `src.process.image.path`, and `src.process.storyline.id` in investigation views. Validate population in the target tenant before production rollout.

## Threat Intelligence context
The **Threat Intelligence** tab consumes native `threat_intelligence_indicators` events and the current TI fields already used in SentinelOne dashboard content:
`tiIndicator.value`, `tiIndicator.type`, `tiIndicator.source`, `tiIndicator.malwareNames`, `tiIndicator.threatActors`, and `event.externalThreatValue`.

Threat Intelligence events are a parallel enrichment signal. They are not a literal SQL-style join between a DNS event and an IOC event. Validate endpoint, process, value, timeline, and Storyline context during investigation.

## NeverOff DNS analytic heuristics
These are **triage heuristics, not SentinelOne threat scores**.

- **NXDOMAIN / resolution-failure focus:** DNS response code `3` is treated as NXDOMAIN.
- **Long request candidate:** request length `>= 80`.
- **Very long request candidate:** request length `>= 120`.
- **Encoded-like label candidate:** long hexadecimal or Base32-like DNS labels.
- **Deep-label candidate:** six or more labels in a DNS name.
- **Burst candidate:** `>= 100` DNS events from the same endpoint/process in a 5-minute bucket.
- **High-unique-domain candidate:** `>= 50` distinct requested domains from the same endpoint/process in a 15-minute bucket.
- **High process DNS count:** `src.process.dnsCount >= 300`.
- **High-abuse TLD watchlist:** `.xyz, .top, .pw, .gq, .ga, .cf, .tk`.
- **Extended elevated-monitoring TLD set:** `.click, .work, .site, .online, .live, .icu, .buzz, .cam, .cyou, .monster, .quest, .sbs`.
- **Dual-use infrastructure:** Dynamic DNS, tunneling/relay services, public paste/CDN/file-transfer services, and encrypted-DNS resolver domains.

All thresholds should be tuned to the client's DNS architecture, recursive resolvers, VPN/proxy model, endpoint role, software inventory, and normal SaaS behavior.

## Important interpretation cautions
- DNS telemetry is **not packet inspection** and does not expose full application-layer payload semantics.
- Long or encoded-looking DNS names are common in legitimate CDN, tracking, EDR, identity, cloud, telemetry, and security products.
- Dynamic DNS, public tunnels, Discord/GitHub/CDN infrastructure, and DoH resolvers are legitimate technologies that are also abused by adversaries.
- A DNS lookup alone does not prove successful network communication or C2.
- High NXDOMAIN volume can come from stale software, search suffixes, typo correction, broken service discovery, ad/tracker blocking, or misconfiguration.
- Beacon-like panels show **repetition/concentration**, not mathematically proven periodicity.
- Use Storyline, process path, command line, user, response data, IP Connect, URL telemetry, and Threat Intelligence before escalation.

## MITRE ATT&CK alignment
Primary operational alignment:
- **T1071.004 — Application Layer Protocol: DNS**
- **T1568.002 — Dynamic Resolution: Domain Generation Algorithms**
- **T1041 — Exfiltration Over C2 Channel**
- **T1095 — Non-Application Layer Protocol** as contextual C2 hunting where DNS-adjacent tooling transitions to custom protocols.

## Recommended SOC workflow
**DNS Command Center → C2 & Abuse Infrastructure → NXDOMAIN → DGA & Domain Anomalies → DNS Tunneling → Threat Intelligence → Endpoint & Process → Investigation → Detection Engineering**


## V1.1 compatibility correction
Dashboard Event Search regular-expression comparisons use `matches`. V1.1 replaces the unsupported `regexp` token in regex-based dashboard panels with `matches`.

Developed by the Threat Detection Engineering Division at NeverOff Technology (SentinelOne Division)
Dominican Republic

---

# Detection Engineering Guidance

Use this tab to validate stable patterns before converting them into **STAR Custom Rules, correlation rules, or SOC playbooks**.

## High-signal single-event candidates
These can be evaluated at the event level after tuning:

**Monitored TLD**
`event.category = "dns" AND event.dns.request contains:anycase(".xyz",".top",".pw",".gq",".ga",".cf",".tk")`

**Very long DNS request**
`event.category = "dns" AND len(event.dns.request) >= 120`

**Encoded-like DNS label**
Use the dashboard's encoded-label regular expression after validating false positives in the tenant.

**Monitored tunnel / relay infrastructure**
Use the embedded tunnel/relay domain list only when the client policy makes those services unauthorized or when additional suspicious context is present.

## Correlation / aggregation candidates
These should not be converted blindly into single-event STAR rules:

- `>=100` DNS events by endpoint + process in 5 minutes.
- `>=50` unique requested domains by endpoint + process in 15 minutes.
- High NXDOMAIN diversity from one endpoint/process.
- Repeated lookups to one domain from the same process across multiple time buckets.
- Long/encoded DNS requests plus suspicious process context.
- DNS anomaly + IP Connect to newly observed infrastructure.
- DNS anomaly + Threat Intelligence IOC hit on the same endpoint/process/time window.

## Recommended response posture
Start with **Alert Only**. After validation, use process termination or Network Quarantine only when the complete Storyline and incident context justify containment.

## Tuning priorities
Exclude or baseline:
- EDR/security products.
- browsers and enterprise updaters where appropriate.
- DNS resolver services.
- cloud/identity agents.
- VPN/ZTNA clients.
- telemetry and observability agents.
- approved Dynamic DNS / tunnel services.
- authorized developer tooling.

The objective is high signal-to-noise, not maximum event volume.

