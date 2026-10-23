# Validation record

## What was checked

- Five source files parse as JSON and use the `TABBED` dashboard structure.
- Every tab has a name and a graphs array; each graph has a title and graph style.
- Every non-Markdown graph in these exports has a query or explicit plot filters.
- Every component has `metadata.yaml` with the required dashboard metadata fields.
- Export copies retain the exact bytes of the supplied source files. Original NeverOff attribution and query logic are preserved.
- No literal email addresses, IPv4 addresses, or UUIDs were found in the JSON string values during the targeted scan. Sensitive configuration key names and common secret formats are separately checked.

Fields such as `site.id`, `agent.uuid`, IP-address fields, and command-line fields are query schema references. Their presence does not mean a tenant ID or customer event was embedded in the export.

The scan is heuristic and cannot establish the absence of every possible confidential value. Embedded public software/domain catalogs and research text require review as part of normal maintenance.

## What was not checked

- Import into a live SentinelOne console.
- Execution of all 374 query panels.
- Field semantics across operating systems, agents, schemas, and tenant versions.
- Runtime, query cost, false-positive rate, or detection coverage.
- Enforcement of the upstream TruffleHog gate, which runs in SentinelOne's contribution workflow.

No synthetic or production query output is presented as an observed validation result.

## Tenant validation plan

1. Record console version, tested operating systems, telemetry coverage, and analyst permissions without publishing tenant identifiers.
2. Import one dashboard in a nonproduction review context. Check tab names, layouts, filters, and graph rendering.
3. Select a short time range and a small endpoint scope. For each tab, execute representative aggregate and investigation queries.
4. Compare panel totals with direct event searches; separately record empty results, missing fields, and parser errors.
5. Confirm that site and endpoint filters constrain all intended panels. Verify DNS TI panels as parallel context rather than event-level joins.
6. Validate login chronology manually, test geography edge cases, and baseline authorized administrative tools.
7. Measure runtime before increasing time range or scope. Record timeout thresholds and large-catalog performance.
8. Document exact failures and fixes in a focused PR. Do not claim every panel passed after testing only representatives.

## Version semantics

JSON `version: 1.0.0` is retained from the source export. Artifact filenames carry the supplied dashboard revision: application/authentication/offensive C2 v1.0, DNS v1.1 compatibility revision, and network geo v2.0. Renaming an artifact does not assert additional runtime validation.
