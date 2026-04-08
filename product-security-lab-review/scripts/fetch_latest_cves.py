#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlparse

from common import fetch_json, normalize_spaces, parse_datetime, to_iso, to_zulu, write_text_output

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
POC_HOST_HINTS = {
    "exploit-db.com",
    "www.exploit-db.com",
    "packetstormsecurity.com",
    "github.com",
    "gist.github.com",
    "gitlab.com",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch recent CVEs from NVD and merge CISA KEV signals.")
    parser.add_argument("--days", type=int, default=7, help="Fetch CVEs published in the last N days when no explicit date range is set.")
    parser.add_argument("--start-date", help="UTC or ISO-8601 start date for NVD pubStartDate.")
    parser.add_argument("--end-date", help="UTC or ISO-8601 end date for NVD pubEndDate.")
    parser.add_argument("--keyword", action="append", default=[], help="Keyword filter applied to NVD and local post-filtering.")
    parser.add_argument("--cpe-name", help="Optional NVD cpeName filter.")
    parser.add_argument("--severity", choices=("LOW", "MEDIUM", "HIGH", "CRITICAL"), help="Post-filter by extracted severity.")
    parser.add_argument("--kev-only", action="store_true", help="Return only CVEs present in the CISA KEV catalog.")
    parser.add_argument("--limit", type=int, default=25, help="Maximum CVEs to emit after filtering.")
    parser.add_argument("--results-per-page", type=int, default=200, help="NVD page size per request.")
    parser.add_argument("--max-pages", type=int, default=10, help="Safety cap for paginated NVD requests.")
    parser.add_argument("--sleep-seconds", type=float, default=6.0, help="Delay between NVD page requests.")
    parser.add_argument("--api-key-env", default="NVD_API_KEY", help="Environment variable containing the NVD API key.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", help="Optional output file path.")
    return parser.parse_args()


def resolve_window(args: argparse.Namespace) -> tuple[datetime, datetime]:
    end = parse_datetime(args.end_date) if args.end_date else datetime.now(UTC)
    start = parse_datetime(args.start_date) if args.start_date else end - timedelta(days=args.days)
    if start >= end:
        raise ValueError("start date must be earlier than end date")
    return start.astimezone(UTC), end.astimezone(UTC)


def severity_from_metrics(metrics: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(metrics, dict):
        return {"severity": None, "score": None, "cvss_version": None, "vector": None}

    candidates = (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    )
    for metric_key, version in candidates:
        metric_entries = metrics.get(metric_key)
        if not isinstance(metric_entries, list):
            continue
        for entry in metric_entries:
            if not isinstance(entry, dict):
                continue
            cvss_data = entry.get("cvssData", {}) if isinstance(entry.get("cvssData"), dict) else {}
            severity = entry.get("baseSeverity") or cvss_data.get("baseSeverity")
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            if severity or score is not None:
                return {
                    "severity": severity,
                    "score": score,
                    "cvss_version": version,
                    "vector": vector,
                }

    return {"severity": None, "score": None, "cvss_version": None, "vector": None}


def english_description(descriptions: list[dict[str, Any]] | None) -> str:
    if not isinstance(descriptions, list):
        return ""
    for description in descriptions:
        if isinstance(description, dict) and description.get("lang") == "en":
            return normalize_spaces(description.get("value"))
    return ""


def unique_reference_urls(references: list[dict[str, Any]] | None) -> list[str]:
    if not isinstance(references, list):
        return []
    seen: set[str] = set()
    urls: list[str] = []
    for reference in references:
        if not isinstance(reference, dict):
            continue
        url = normalize_spaces(reference.get("url"))
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def reference_details(references: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not isinstance(references, list):
        return []

    details: list[dict[str, Any]] = []
    seen: set[str] = set()
    for reference in references:
        if not isinstance(reference, dict):
            continue
        url = normalize_spaces(reference.get("url"))
        if not url or url in seen:
            continue
        seen.add(url)
        tags = reference.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        details.append(
            {
                "url": url,
                "source": reference.get("source"),
                "tags": [str(tag) for tag in tags],
            }
        )
    return details


def advisory_urls(reference_items: list[dict[str, Any]]) -> list[str]:
    urls: list[str] = []
    for item in reference_items:
        tags = {tag.lower() for tag in item.get("tags", [])}
        if "vendor advisory" in tags or "patch" in tags or "release notes" in tags or "us government resource" in tags:
            urls.append(item["url"])
    return urls


def public_poc_urls(reference_items: list[dict[str, Any]]) -> list[str]:
    urls: list[str] = []
    for item in reference_items:
        url = item["url"]
        tags = {tag.lower() for tag in item.get("tags", [])}
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()
        path = (parsed.path or "").lower()

        has_explicit_exploit_tag = "exploit" in tags
        has_poc_hint = any(token in url.lower() for token in ("poc", "proof-of-concept", "exploit"))
        host_looks_relevant = host in POC_HOST_HINTS and has_poc_hint

        if has_explicit_exploit_tag or host_looks_relevant:
            urls.append(url)
    return urls


def summarize_mechanism(text: str) -> str:
    normalized = normalize_spaces(text)
    if not normalized:
        return ""

    sentences = [segment.strip() for segment in normalized.split(". ") if segment.strip()]
    if not sentences:
        return normalized[:320]

    summary = ". ".join(sentences[:2]).strip()
    if not summary.endswith("."):
        summary += "."
    return summary[:420]


def cpe_to_label(criteria: str) -> str:
    parts = criteria.split(":")
    if len(parts) < 6:
        return criteria

    vendor = parts[3]
    product = parts[4]
    version = parts[5]
    base = f"{vendor}:{product}"
    if version and version != "*":
        return f"{base} {version}"
    return base


def format_version_bounds(match: dict[str, Any], criteria: str) -> str:
    constraints: list[str] = []
    exact = cpe_to_label(criteria)

    if match.get("versionStartIncluding"):
        constraints.append(f">={match['versionStartIncluding']}")
    if match.get("versionStartExcluding"):
        constraints.append(f">{match['versionStartExcluding']}")
    if match.get("versionEndIncluding"):
        constraints.append(f"<={match['versionEndIncluding']}")
    if match.get("versionEndExcluding"):
        constraints.append(f"<{match['versionEndExcluding']}")

    if constraints:
        base = cpe_to_label(":".join(criteria.split(":")[:5] + ["*"]))
        return f"{base} {', '.join(constraints)}"
    return exact


def _walk_configuration_nodes(node: Any, output: list[str]) -> None:
    if isinstance(node, list):
        for item in node:
            _walk_configuration_nodes(item, output)
        return

    if not isinstance(node, dict):
        return

    cpe_matches = node.get("cpeMatch", [])
    if isinstance(cpe_matches, list):
        for match in cpe_matches:
            if not isinstance(match, dict) or not match.get("vulnerable"):
                continue
            criteria = normalize_spaces(match.get("criteria"))
            if not criteria:
                continue
            output.append(format_version_bounds(match, criteria))

    for child_key in ("nodes", "children"):
        child = node.get(child_key)
        if child:
            _walk_configuration_nodes(child, output)


def affected_versions(configurations: list[dict[str, Any]] | None) -> list[str]:
    collected: list[str] = []
    _walk_configuration_nodes(configurations, collected)
    deduped: list[str] = []
    seen: set[str] = set()
    for item in collected:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def normalize_cve(cve: dict[str, Any]) -> dict[str, Any]:
    severity = severity_from_metrics(cve.get("metrics"))
    cve_id = cve["id"]
    published = parse_datetime(cve.get("published"))
    last_modified = parse_datetime(cve.get("lastModified"))
    description = english_description(cve.get("descriptions"))
    references = reference_details(cve.get("references"))
    affected = affected_versions(cve.get("configurations"))

    return {
        "cve_id": cve_id,
        "published": to_iso(published),
        "last_modified": to_iso(last_modified),
        "status": cve.get("vulnStatus"),
        "summary": description,
        "mechanism_summary": summarize_mechanism(description),
        "severity": severity["severity"],
        "score": severity["score"],
        "cvss_version": severity["cvss_version"],
        "vector": severity["vector"],
        "source_identifier": cve.get("sourceIdentifier"),
        "references": unique_reference_urls(cve.get("references")),
        "reference_details": references,
        "advisory_urls": advisory_urls(references),
        "public_poc_urls": public_poc_urls(references),
        "affected_versions": affected,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "kev": False,
        "kev_date_added": None,
        "kev_vendor_project": None,
        "kev_product": None,
        "kev_ransomware_use": None,
    }


def fetch_kev_map(timeout: int) -> dict[str, dict[str, Any]]:
    payload, _ = fetch_json(CISA_KEV_JSON, timeout=timeout)
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    kev_map: dict[str, dict[str, Any]] = {}
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        cve_id = normalize_spaces(vulnerability.get("cveID")).upper()
        if not cve_id:
            continue
        kev_map[cve_id] = vulnerability
    return kev_map


def keyword_match(record: dict[str, Any], keywords: list[str]) -> bool:
    if not keywords:
        return True
    haystack = " ".join(
        [
            record.get("cve_id") or "",
            record.get("summary") or "",
            " ".join(record.get("references", [])),
            record.get("kev_vendor_project") or "",
            record.get("kev_product") or "",
        ]
    ).lower()
    return all(keyword.lower() in haystack for keyword in keywords)


def merge_kev(record: dict[str, Any], kev_map: dict[str, dict[str, Any]]) -> None:
    kev_entry = kev_map.get(record["cve_id"].upper())
    if not kev_entry:
        return
    record["kev"] = True
    record["kev_date_added"] = kev_entry.get("dateAdded")
    record["kev_vendor_project"] = kev_entry.get("vendorProject")
    record["kev_product"] = kev_entry.get("product")
    record["kev_ransomware_use"] = kev_entry.get("knownRansomwareCampaignUse")


def build_nvd_url(
    *,
    start: datetime,
    end: datetime,
    start_index: int,
    results_per_page: int,
    keywords: list[str],
    cpe_name: str | None,
) -> str:
    query = {
        "pubStartDate": to_zulu(start),
        "pubEndDate": to_zulu(end),
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }
    if keywords:
        query["keywordSearch"] = " ".join(keywords)
    if cpe_name:
        query["cpeName"] = cpe_name
    return f"{NVD_CVE_API}?{urlencode(query)}"


def fetch_nvd_payload(url: str, headers: dict[str, str], timeout: int, attempts: int = 3) -> dict[str, Any]:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            payload, _ = fetch_json(url, headers=headers, timeout=timeout)
            if isinstance(payload, dict):
                return payload
            raise ValueError("unexpected NVD payload type")
        except Exception as exc:  # pragma: no cover
            last_error = exc
            if attempt >= attempts:
                break
            time.sleep(min(2 * attempt, 6))

    if last_error is None:
        raise RuntimeError("failed to fetch NVD payload")
    raise last_error


def collect_nvd_records(args: argparse.Namespace, start: datetime, end: datetime) -> tuple[list[dict[str, Any]], bool]:
    headers: dict[str, str] = {}
    api_key = os.getenv(args.api_key_env)
    if api_key:
        headers["apiKey"] = api_key

    collected: list[dict[str, Any]] = []
    truncated = False
    start_index = 0
    page_count = 0

    while True:
        url = build_nvd_url(
            start=start,
            end=end,
            start_index=start_index,
            results_per_page=args.results_per_page,
            keywords=args.keyword,
            cpe_name=args.cpe_name,
        )
        payload = fetch_nvd_payload(url, headers=headers, timeout=args.timeout)
        vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        total_results = int(payload.get("totalResults", 0)) if isinstance(payload, dict) else 0
        page_size = int(payload.get("resultsPerPage", len(vulnerabilities) or args.results_per_page)) if isinstance(payload, dict) else args.results_per_page

        for vulnerability in vulnerabilities:
            cve = vulnerability.get("cve") if isinstance(vulnerability, dict) else None
            if isinstance(cve, dict) and cve.get("id"):
                collected.append(normalize_cve(cve))

        page_count += 1
        start_index += page_size
        if start_index >= total_results or not vulnerabilities:
            break
        if page_count >= args.max_pages:
            truncated = True
            break
        time.sleep(args.sleep_seconds)

    return collected, truncated


def apply_filters(records: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for record in records:
        if args.kev_only and not record["kev"]:
            continue
        if args.severity and (record["severity"] or "").upper() != args.severity:
            continue
        if not keyword_match(record, args.keyword):
            continue
        filtered.append(record)

    filtered.sort(
        key=lambda record: (
            record["published"] or "",
            record["last_modified"] or "",
            SEVERITY_ORDER.get((record["severity"] or "").upper(), 0),
            record["cve_id"],
        ),
        reverse=True,
    )
    if args.limit > 0:
        filtered = filtered[: args.limit]
    return filtered


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Latest CVEs",
        "",
        f"Generated at: {payload['generated_at']}",
        f"Window: {payload['window']['start']} -> {payload['window']['end']}",
        "",
    ]
    if payload["truncated"]:
        lines.append("Warning: pagination stopped at max-pages before the full result set was collected.")
        lines.append("")
    for item in payload["items"]:
        severity = item["severity"] or "UNKNOWN"
        kev_flag = "KEV" if item["kev"] else "NVD"
        published = item["published"] or "unknown-date"
        lines.append(f"- {item['cve_id']} | {published} | {severity} | {kev_flag}")
        lines.append(f"  {item['summary']}")
        lines.append(f"  {item['nvd_url']}")
    if not payload["items"]:
        lines.append("No CVEs matched the requested filters.")
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    args = parse_args()
    try:
        start, end = resolve_window(args)
        kev_map = fetch_kev_map(args.timeout)
        records, truncated = collect_nvd_records(args, start, end)
        for record in records:
            merge_kev(record, kev_map)
        filtered_records = apply_filters(records, args)

        payload = {
            "generated_at": to_iso(datetime.now(UTC)),
            "window": {"start": to_iso(start), "end": to_iso(end)},
            "official_sources": {
                "nvd": NVD_CVE_API,
                "cisa_kev": CISA_KEV_JSON,
            },
            "truncated": truncated,
            "total_collected": len(records),
            "items": filtered_records,
        }

        if args.format == "json":
            output = json.dumps(payload, indent=2, ensure_ascii=False)
        else:
            output = render_markdown(payload)
        write_text_output(output, args.output)
        return 0
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
