---
name: product-security-lab-review
description: Collect recent product or release announcements, correlate current CVEs, CISA KEV entries, and vendor advisories, and perform defensive local-lab security review for software the user is authorized to test. Use when Codex needs to assess a newly released product or version, build a cited exposure summary, inspect dependencies, configuration, or artifacts in a local lab, or draft remediation guidance. Do not use for exploit development, attack automation, credential attacks, unauthorized scanning, or persistence.
---

# Product Security Lab Review

## Overview

Use this skill for defensive security research on newly released software, packages, images, or appliances that the user is authorized to assess in a local lab.

Turn the request into a bounded workflow:

1. confirm the target and authorization
2. gather release intelligence from current official sources
3. correlate live CVE and advisory data
4. perform safe, non-destructive local-lab review
5. produce a cited risk and remediation report

If the user asks for exploitation, payloads, bypasses, weaponization, or internet-wide targeting, refuse that part and pivot to detection, validation, and remediation.

## Quick Start

Use the bundled scripts for the two time-sensitive collection tasks:

- `scripts/fetch_vendor_releases.py`: collect recent items from official vendor release, advisory, or changelog pages
- `scripts/fetch_latest_cves.py`: pull recent NVD CVEs and merge current CISA KEV signals
- `scripts/build_security_digest.py`: batch-run release and CVE collection, compare with the previous state, and generate date-grouped digest reports under `日报内容\<日期>`
- `scripts/run_security_digest.ps1`: run the digest with log capture from PowerShell
- `scripts/register_daily_digest_task.ps1`: register a daily Windows scheduled task for digest generation

Example commands:

```bash
python scripts/fetch_vendor_releases.py --url "https://blog.python.org/" --vendor "Python" --product "Python Blog" --keyword release --limit 5 --format markdown
python scripts/fetch_latest_cves.py --days 7 --keyword nginx --limit 10 --format markdown
python scripts/build_security_digest.py --config ./digest-config.json --output-root ./security-output --format markdown
powershell -ExecutionPolicy Bypass -File .\scripts\register_daily_digest_task.ps1 -ConfigPath .\digest-config.json -OutputRoot .\security-output -ScheduleTime 22:00 -Force
```

For multi-source vendor collection, use the config shape documented in [vendor-source-config.md](references/vendor-source-config.md).
For recurring digest runs, use the config shape documented in [digest-config.md](references/digest-config.md).
For daily Windows scheduling, use [scheduler.md](references/scheduler.md).

## Required Guardrails

- Work only on software, images, packages, containers, or lab instances the user owns or is explicitly authorized to assess.
- Keep all active testing inside a local, isolated lab. Do not touch third-party hosts or public targets.
- Stay non-destructive. Prefer inspection, version comparison, configuration review, dependency analysis, log review, and vendor patch diffing over active exploitation.
- Do not generate exploit code, payloads, persistence steps, credential attacks, or instructions to bypass authentication or gain execution.
- When the request contains "latest", "newest", "today", or similar language, browse current sources and cite them. Do not rely on memory for volatile security information.

## Workflow

### 1. Confirm The Target

Collect:

- vendor, product, version, release date, platform, and packaging format
- local lab artifacts available for review such as installers, containers, firmware, SBOMs, repos, or documentation
- the explicit authorization boundary

If the exact version is unknown, identify it before making claims about CVE applicability.

### 2. Gather Release Intelligence

Prefer official sources first:

- vendor release notes
- vendor security advisories
- official documentation or download pages
- package or container registry metadata

Record:

- exact version string
- release or publish date
- notable security-relevant changes
- bundled components or dependencies that may have separate advisories

Use [source-priority.md](references/source-priority.md) for source order and search patterns.

Use `scripts/fetch_vendor_releases.py` when the work begins with one or more official release pages. Prefer `mode=auto` so the script tries feed discovery first and falls back to HTML link extraction.

### 3. Correlate Live Vulnerability Intelligence

Check current sources in this order:

- vendor advisory
- CISA KEV
- NVD
- MITRE CVE
- ecosystem advisory database when relevant, such as GitHub Advisory Database

For each candidate issue, capture:

- CVE ID
- affected versions and fixed versions
- exploitation status if a source explicitly states it
- CVSS or severity if present
- evidence tying the issue to the target version or bundled component
- mitigation or upgrade path

Do not infer impact from the title alone. If version mapping is ambiguous, say it is unconfirmed.

Use `scripts/fetch_latest_cves.py` for current CVE intake. The script queries the official NVD CVE 2.0 API and merges the official CISA KEV JSON catalog so the output already flags known exploited items.

For repeated monitoring, prefer `scripts/build_security_digest.py`. It reuses release collection and CVE collection, compares the result with the previous cached snapshot, and emits a digest focused on newly seen items.

### 4. Run Safe Local-Lab Review

Allowed local techniques:

- inventory files, packages, services, ports, endpoints, and bundled libraries
- extract or generate SBOMs and compare versions against advisories
- review default configs, hardening settings, exposed management surfaces, and insecure defaults
- inspect logs, headers, banners, manifests, lockfiles, container layers, and build metadata
- perform static analysis or diff vendor patches to understand exposure at a high level
- validate whether a risky code path or feature is present without using exploit payloads

Avoid:

- exploit attempts
- auth bypass attempts
- brute force or credential stuffing
- destructive fuzzing
- persistence or lateral movement
- any testing against systems outside the isolated lab

Use [lab-checklist.md](references/lab-checklist.md) to keep the review bounded.

### 5. Deliver The Report

Use the template in [report-template.md](references/report-template.md).

Separate:

- confirmed facts with citations
- local observations from the lab
- inferred risks that still need confirmation
- recommended mitigations in priority order
- unresolved questions

## Output Rules

- Cite every time-sensitive claim with a current source.
- Prefer exact versions and dates over vague wording.
- Distinguish product-level issues from dependency-level issues.
- If no confirmed CVE applies, say that explicitly and list what was checked.
- If the user tries to expand scope toward offensive use, keep the work defensive and bounded.

## Script Notes

- Respect NVD rate limits. Without an API key, the official public limit is 5 requests per rolling 30-second window. The bundled CVE script sleeps between paginated requests by default.
- Keep vendor collection pointed at official pages only. Do not switch to mirrors, reposts, or forum copies unless the user explicitly asks for broader coverage.
- Treat script output as intake, not final truth. Confirm applicability against exact versions before reporting confirmed exposure.
- Schedule recurring runs outside the skill, for example with Windows Task Scheduler or cron. The skill only performs collection and report generation; it does not install persistence or background services.
