# Source Priority

## Priority Order

Use current sources in this order whenever the request depends on recent vulnerability or release information:

1. vendor security advisory
2. vendor release notes or changelog
3. CISA Known Exploited Vulnerabilities catalog
4. NVD
5. MITRE CVE
6. ecosystem advisory database when the product bundles a package or library

Treat vendor statements about affected and fixed versions as the highest-confidence source when they exist.

## Search Patterns

Start with narrow, version-aware queries:

- `"<vendor> <product> <version> release notes"`
- `"<vendor> <product> <version> security advisory"`
- `site:cisa.gov "<product>" CVE`
- `site:nvd.nist.gov "<product>" "<version>"`
- `site:cve.org "<product>" "<version>"`

If the product bundles third-party components, search those components separately and record whether the issue is product-level or dependency-level.

## Correlation Rules

- Prefer exact version matches over family-level matches.
- Record publication and last-modified dates for volatile records.
- Do not assume a CVE applies just because the product name matches.
- Note when a product bundles a vulnerable component but the vendor has backported a fix.
- If sources conflict, cite the conflict instead of collapsing it into a single claim.
