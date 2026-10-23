# Global Network Intelligence — Geo Connections & Exposure | V2

This dashboard turns **SentinelOne IP Connect telemetry** into an analyst-focused network intelligence view for SOC operations.

## Primary use cases
- Identify **outbound connections** by destination country, remote IP, protocol, port, endpoint, process, and user.
- Identify **inbound connections** by source country, source IP, destination endpoint, service port, and process.
- Provide **all-country traffic visibility** across every geolocatable remote country observed in the selected time range.
- Rank countries, IPs, endpoints, processes, users, protocols, and ports by observed connection volume.
- Investigate policy-defined restricted/elevated-risk geographies.
- Surface network activity involving **remote administration, lateral-movement, database, and other security-sensitive service ports**.
- Pivot from geography → endpoint → process through Sankey visualizations.
- Provide raw event tables for investigation and evidence collection.

## Important interpretation notes
- Country attribution is derived from public IP geolocation using `geo_ip_country()`.
- Private, loopback, link-local, or otherwise non-geolocatable addresses may not produce a country value.
- NAT, proxies, VPNs, CDNs, cloud egress, and security gateways can change the apparent country associated with a connection.
- A connection to a restricted or monitored country is **not by itself evidence of malicious activity**. Geography is a policy/risk signal that requires endpoint, process, port, user, and Storyline context.
- Event counts are connection-event counts, not guaranteed unique TCP/UDP sessions.
- This dashboard is based primarily on `event.type == "IP Connect"` telemetry collected by SentinelOne-protected endpoints.

## V2 policy-defined restricted / elevated-risk geographies
The **Restricted Geographies** tab monitors the following country set:

**Tier 1 — Persistent state-sponsored / strategic cyber threat focus**
- Russia
- China
- Iran
- North Korea / DPRK
- Belarus

**Tier 2 — Elevated APT monitoring / client risk policy**
- India
- Pakistan
- Vietnam

The list is intentionally policy-driven and can be customized per client. Country-level monitoring should not be interpreted as attribution of individual traffic to a threat actor.

## V2 all-country visibility
The **Geo Intelligence** tab includes an **All Countries — Unified Traffic Matrix**. It groups all geolocatable inbound and outbound IP Connect events by remote country and direction, including connection volume, unique remote IPs, endpoints, processes, protocols, and observed ports.

## Analytic Priority model
The Restricted Geographies tab includes a **custom analytic score** for triage. This is not a SentinelOne threat score:
- +50: Tier 1 restricted geography
- +35: Tier 2 elevated-monitoring geography
- +30: security-sensitive destination/service port
- +20: script interpreter / LOLBin / command-line utility process

The score is intended only to prioritize analyst review.

## V2 query compatibility fix
The **Monitored Geography Activity Over Time** visualization uses a full Power Query with `timebucket()` and `transpose` instead of dashboard regular-search plot filters. This avoids using `geo_ip_country()` in a regular-search plot filter, where that function is not supported.

Developed by the Threat Detection Engineering Division at NeverOff Technology (SentinelOne Division)
Dominican Republic
