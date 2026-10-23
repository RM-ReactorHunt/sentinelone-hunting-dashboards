# SentinelOne Hunting Dashboards

### Threat intelligence → hunting context → analyst decisions

A community collection of five SentinelOne Singularity Data Lake / AI SIEM dashboard exports for Threat Hunting, Detection Engineering, and SOC investigation.

**5 dashboards · 44 tabs · 383 panels · 374 query panels**

Maintained by [RM-ReactorHunt](https://github.com/RM-ReactorHunt). Original development credit: **Threat Detection Engineering Division, NeverOff Technology (SentinelOne Division), Dominican Republic**. The original attribution is preserved inside every export.

This is an independent community contribution. Publication here does not indicate SentinelOne acceptance, certification, or official product support.

## Dashboard catalog

| Dashboard | Analyst objective | Tabs | Panels | Query panels |
| --- | --- | ---: | ---: | ---: |
| [Application Risk Intelligence](dashboards/community/sentinelone-application-risk-intelligence-latest/) | Investigate PUA, shadow software, tool execution, data movement, and execution origins | 8 | 79 | 78 |
| [Authentication Threat Intelligence](dashboards/community/sentinelone-authentication-threat-intelligence-latest/) | Triage failed logins, password spraying, privileged access, and account targeting | 9 | 57 | 55 |
| [DNS, C2 & Anomaly Intelligence](dashboards/community/sentinelone-dns-c2-anomaly-intelligence-latest/) | Investigate DNS anomalies, resolution failures, tunneling candidates, and TI context | 10 | 98 | 96 |
| [Global Network & Geo Intelligence](dashboards/community/sentinelone-global-network-geo-intelligence-latest/) | Analyze IP Connect activity, geography, exposure, ports, and process attribution | 9 | 74 | 71 |
| [Offensive Security & C2 Intelligence](dashboards/community/sentinelone-offensive-security-c2-intelligence-latest/) | Investigate offensive tools, C2 candidates, process lineage, and Storyline context | 8 | 75 | 74 |

Panel counts include nine embedded Markdown panels. Query counts describe the exports, not independently validated detections. Overlapping dashboards should not be treated as 374 distinct detection rules.

## Import a dashboard

1. Open its catalog directory and download the versioned `.json` file. The JSON is the import artifact; `metadata.yaml` describes its dependencies and `RESEARCH_NOTES.md` mirrors its embedded documentation.
2. Confirm access to SentinelOne Singularity Data Lake / AI SIEM dashboards, endpoint telemetry, and the applicable data retention and feature entitlements.
3. Use your console's dashboard import capability to import the JSON. Labels and import availability can differ between console releases; consult your tenant's documentation or administrator.
4. Start with a short time range and a small site or endpoint scope. Verify the field coverage listed in `metadata.yaml` before expanding the search.
5. Compare representative panels against the underlying events. Document query errors, missing fields, performance, and expected benign matches before using results operationally.

The exports contain dashboard definitions and queries, not captured customer event results. They do not deploy STAR rules, containment actions, or response playbooks. Importing a dashboard creates a dashboard object in your tenant; running panels queries your tenant's data.

## Validation status

**Static validation only for this community release.** JSON parsing, basic export structure, graph/query counts, retained source-byte hashes, and a targeted scan for obvious sensitive literals are checked locally. These checks do not prove query syntax compatibility, import success, field coverage, detection efficacy, or query performance in a SentinelOne tenant.

See [VALIDATION.md](VALIDATION.md) for scope and a reproducible tenant validation plan. Use `node scripts/validate.mjs` to repeat the static checks with Node.js 18 or newer; no packages, credentials, or network access are required.

## Interpretation and tuning

- Name matching and embedded catalogs are hunting leads. Legitimate administration, DFIR, development, and authorized Red Team activity can match them; renamed tools can evade them.
- Custom priority scores and thresholds are analyst heuristics, not native SentinelOne severities or proof of compromise.
- DNS repetition is not proof of periodic beaconing. Long labels and high NXDOMAIN volume require context.
- Authentication failure/success coexistence does not prove that success followed failures. Confirm event chronology.
- Geography is a configurable policy signal. VPNs, CDNs, NAT, and cloud infrastructure can alter apparent location; country alone is not evidence of an attack.
- The offensive-security dashboard is inspired by RedEye investigation concepts. It does not import RedEye code or require RedEye, and endpoint telemetry does not directly identify a C2 operator.
- Use focused scopes and time ranges. The large process catalogs and aggregate panels require tenant-specific performance review.

## Contributing upstream

The intended upstream is [Sentinel-One/ai-siem](https://github.com/Sentinel-One/ai-siem), under `dashboards/community/`. This repository follows its per-dashboard layout and `metadata.yaml` convention.

Its [contribution guide](https://github.com/Sentinel-One/ai-siem/blob/main/CONTRIBUTING.md) asks contributors to open an issue before proposing multiple components and to keep PRs focused. The initial step is a scope proposal, followed by focused dashboard PRs after maintainer alignment. No upstream approval is implied by this release.

## Feedback and collaboration

Open an issue with the dashboard name, console version, affected panel, sanitized query error, and reproduction steps. Do not post customer data, tenant identifiers, credentials, or unredacted console screenshots.

[GitHub profile](https://github.com/RM-ReactorHunt) · [LinkedIn](https://www.linkedin.com/in/rainieri-marmolejos-cabrera-0b2754103/)

## License and attribution

Released under [GNU AGPL-3.0](LICENSE), with the contributor's authorization to publish these exports under that license. Preserve the NeverOff development attribution. Product and framework names belong to their respective owners.
