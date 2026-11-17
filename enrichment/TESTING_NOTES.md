# Evidence state on November 16, 2026

The original GitHub 170-row indicator matrix permits exact membership counts and prefix analysis. It **does not** contain per-IP ASN, country, port inventory, HTTP title, or full `robots.txt` / `sitemap.xml` bodies for all candidates. No Censys API credential or additional 170-host Censys export was available in this session; therefore the ASN/country/title/TCP-5000 prevalences and 139-candidate normalization numerator remain *unmeasured*.

Independent measurements of the committed matrix:

| Combination | Unlisted | Published | Total |
| --- | ---: | ---: | ---: |
| A only | 7 | 5 | 12 |
| B only | 11 | 2 | 13 |
| C only | 42 | 0 | 42 |
| A and B only | 29 | 16 | 45 |
| A and C only | 17 | 0 | 17 |
| B and C only | 13 | 2 | 15 |
| A and B and C | 20 | 6 | 26 |
| **Total** | **139** | **31** | **170** |

Network aggregation: **128 unique `/24` IPv4 prefixes**, **20 prefixes** with >1 recovered IP. Top prefixes (number of recovered IPs): `108.186.202.0/24` 8; `95.133.228.0/24` 7; `95.133.229.0/24` 5; `95.133.230.0/24` 5; `45.61.178.0/24` 4; `64.224.17.0/24` 3; `108.165.15.0/24` 3; `140.150.232.0/24` 3.

Published-reference labels in the matrix: `BlackApex` 15; `DarkApex` 5; `OGPARKER1` 2; `W1-TOKEN` 1; `XXX101-TOKEN` 3; `403 Forbidden` 1; `@globaltoken1` 4. These are **reported panel labels**, not seven distinct adversary actors.

DO NOT fill missing enrichment fields with zeros or add invented metadata to the final report.
