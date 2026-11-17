# BlackApex Capstone — passive Censys enrichment and normalized-template evaluation

**Purpose:** extend the already published 170-IP membership dataset with reproducible host-level enrichment. These scripts perform **no active scanning** or phishing-site interaction. The only network calls are to the authenticated Censys Platform API.

## Setup (from the GitHub repository root)

1. Copy `collect_censys.py` and `analyze_censys.py` into `enrichment/` (create that folder).
2. Preserve your existing `experiments/indicator_overlap/Component7_BlackApex_Indicator_Matrix.csv` without alteration.
3. Set `CENSYS_PAT` as a Codespaces **secret or shell environment variable**. Never commit a token or paste it into the notebook/repository. Set optional `CENSYS_ORG_ID` for your organization's tier.
4. Check account API permissions and remaining credits before collecting. Censys provides an authenticated **POST /v3/global/asset/host** endpoint for **up to 100 hosts per call**; the plan controls data visibility and historical retrieval. Censys Free credits are limited. A batch request does **not** imply its returned observations are from November 11–13.

```bash
python enrichment/collect_censys.py --limit 10                 # Dry run, no API calls
python enrichment/collect_censys.py --limit 10 --execute --out-dir enrichment/pilot_raw  # Pilot 10 hosts
python enrichment/collect_censys.py --limit 170 --execute      # Full sample, one or more batches
python enrichment/analyze_censys.py                           # Offline tabulation
```

**Historical alternative (if your Censys entitlement supports November 12 records):**

```bash
python enrichment/collect_censys.py --limit 170 --at-time 2026-11-12T12:00:00Z --out-dir enrichment/raw_historical --execute
python enrichment/analyze_censys.py --raw-dir enrichment/raw_historical --out-dir enrichment/results_historical
python enrichment/analyze_censys.py
```

If Censys responds that historical access is unavailable, run a *current* lookup instead, and label the result **November 16-or-later snapshot** rather than retroactively claiming it represents the original collection period. Do not mix current and historical response files in a single report; move old JSON elsewhere first. Re-running `collect_censys.py` skips existing batches only if their requested IP list and snapshot time match exactly; it stops on mismatches instead of silently mixing pilot/full or historical/current results. Do not treat a missing host, absent metadata field, or unavailable HTTP body as a negative match.

## Files produced

- `enrichment/raw/censys_hosts_batch_XX.json`: unmodified API body, with requested IPs and retrieval/snapshot provenance.
- `enrichment/results/hosts_enriched.csv`: one row per original IP, including ASN, network name, country, observed ports and observed HTTP title *when present*.
- `enrichment/results/template_evaluation.csv`: endpoint- and port-specific evidence status, independently verified SHA-256, and normalized template correspondence.
- `enrichment/results/analysis_summary.json`: observed-only prevalence figures and explicit denominators; includes exact CSV membership counts even if the API is unavailable.
- `enrichment/results/provenance_manifest.csv`: links each host to a saved source batch and timestamp.

## Interpret normalized matches correctly

The reference bodies are `experiments/structural/samples/192_166_82_111_https443_sitemap.xml` and `experiments/structural/samples/192_166_82_111_port5000_robots.txt`.

For a Censys endpoint to be **evaluable**, the retrieved complete text must hash to its *own* contemporaneously recorded `http.body_hash_sha256`, the HTTP path must be `/sitemap.xml` or `/robots.txt`, and precisely one qualifying embedded domain must be normalizable. These rules minimize false correspondences produced by missing/truncated bodies and path confusion.

A **normalized match** means that the hash of the canonically normalized verified body equals the hash of the equivalently normalized reference of the same resource kind. This is **not** an attribution, confirmation of malicious behavior, or even proof of the same operator. For comparison, the earlier known candidate `140.150.232.108` was reconstructed from reference bytes; its two SHA-256 reproductions are valid experimental evidence but must **not** be silently counted as an independently collected second host response in this population test.

Report `X / N evaluable unlisted hosts, out of 139 total unlisted`, not `X / 139`, unless all 139 have separately verified comparison bodies. A host with a Censys record but no retained sitemap/robots body has unknown template status. A live host that no longer exposes the resource is a valid *as-of-now* nonobservation, not necessarily historical absence.

## Limits and ethics

- An ASN or country is an IP allocation/routing or geolocation property, not the attacker's physical location.
- TCP/5000 counts are observations for services returned at the specified time, not historical exposure unless an entitled historical query is used.
- `/24` prefix sharing is not proof of shared infrastructure ownership or criminal control.
- HTML `title` is counted only when actually provided by the Censys response. A host can expose multiple HTTP titles, so per-title totals may exceed host counts.
- Censys documents that HTTP bodies may be indexed only up to the first 64 KiB; if a full-body digest cannot be reproduced, the sample is not accepted as a verified byte comparator.
- The API might return fields in a tier- or schema-dependent format. If `analyze_censys.py` rejects a JSON shape, inspect its error; do not modify counts manually to force success.
- Follow Censys terms. Do not query external phishing sites, submit authentication codes, or collect tokens.

### Sources

- [Censys Platform API authentication and privileges](https://docs.censys.com/reference/get-started)
- [Retrieve multiple hosts (up to 100 per API call)](https://docs.censys.com/reference/v3-globaldata-asset-host-list-post)
- [Censys host data schema, services and HTTP body limits](https://docs.censys.com/docs/platform-host-dataset)
- [Historical host lookup fields and entitlements](https://docs.censys.com/reference/v3-globaldata-asset-host)
