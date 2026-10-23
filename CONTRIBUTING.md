# Contributing

Open a focused issue or pull request for one dashboard. Include the purpose, data dependencies, tested console version, affected panels, and validation evidence.

Preserve original attribution and the AGPL-3.0 license. Do not submit credentials, tenant IDs, customer names, internal hostnames, real event exports, or unredacted screenshots. Keep dashboard exports under `dashboards/community/<name>-latest/`, with a versioned JSON filename, `metadata.yaml`, and matching research notes.

Run `node scripts/validate.mjs`. For query changes, also test in an authorized SentinelOne tenant and describe the scope actually tested. Static parsing alone does not establish query validity.

For upstream submissions, follow [Sentinel-One/ai-siem's contribution guide](https://github.com/Sentinel-One/ai-siem/blob/main/CONTRIBUTING.md), including prior discussion for multi-component work and a focused PR per component.
