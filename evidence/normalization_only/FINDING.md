# BA-NORM-001: Configuration-Normalized HTTP Template Match

## Research objective

Evaluate whether configuration normalization can identify
template-correlated infrastructure missed by exact SHA-256
fingerprint matching.

## Candidate

- IP: 140.150.232.108
- Published LevelBlue IOC status: Unlisted
- Censys scan timestamp: 2026-11-16 07:50:54 UTC
- Collection method: Censys Platform API v3 host lookup

## Evidence

| Resource | Candidate SHA-256 | Exact reference match | Normalized reference match |
|---|---|---|---|
| /robots.txt | 3badb5b0b4ca9a261a19463465b3f4dad425820d00be40a0f4692ef0bfc4ea73 | No | Yes |
| /sitemap.xml | 84c27062a2361d21f0800e392603de3a687d155ab12891d1143d544f763f817e | No | Yes |

Reference SHA-256 fingerprints:

- robots.txt: 831a8dec4cd5c41ec5f7cb61e9add4e547d564f207f75c053aee19f6f0cf6135
- sitemap.xml: 5ec645bf49961d0f1b14e5ddc354e44df42b75b4451c19c6362e6a1d829a917f

Both candidate HTTP response bodies were independently recovered
through Censys. Their locally calculated SHA-256 hashes matched
the hashes recorded in the API responses.

Both differed from the corresponding reference fingerprints but
matched following configuration normalization.

## Methodology

1. Retrieved the candidate's current Censys host record.
2. Extracted observed robots.txt and sitemap.xml response bodies.
3. Calculated local SHA-256 hashes.
4. Compared local hashes against the Censys-recorded hashes.
5. Compared exact hashes against preserved reference files.
6. Applied the toolkit's configuration-normalization procedure.
7. Recorded normalized-template matches and scan timestamps.

## Interpretation

The candidate demonstrates a normalization-only template
correspondence: exact reference hashes do not match, but both
normalized static resources match their reference templates.

This supports the incremental value of normalization for the
selected candidate.

## Limitations

- Template correspondence does not prove malicious activity,
  common ownership, or shared operator control.
- The candidate was selected deliberately, not randomly.
- This observation cannot establish normalization-only match
  prevalence across the full 170-IP dataset.
- Censys scan timestamps are observation times, not deployment
  or compromise timestamps.
- Historical availability and changes between scans remain
  outside the scope of this verification.

## Supporting artifacts

- evidence/normalization_only/template_evaluation.csv
- evidence/normalization_only/hosts_enriched.csv
- evidence/normalization_only/SHA256SUMS.txt
- experiments/structural/samples/
- enrichment/analyze_censys.py
- enrichment/collect_censys.py

The original Censys API response is retained privately at:
enrichment/onedrive_raw/censys_hosts_batch_01.json

Its integrity hash is recorded in SHA256SUMS.txt.
The private response is not included in the public repository.
