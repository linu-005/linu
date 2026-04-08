#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

from common import normalize_spaces, to_iso, write_text_output
from fetch_latest_cves import apply_filters, collect_nvd_records, fetch_kev_map, merge_kev, resolve_window
from fetch_vendor_releases import ReleaseSource, collect_from_source


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run release collection and CVE collection, cache snapshots, and build a digest report.")
    parser.add_argument("--config", required=True, help="Path to the digest JSON config.")
    parser.add_argument("--output-root", required=True, help="Directory used for snapshots, latest copies, and reports.")
    parser.add_argument("--timestamp", help="Override timestamp in YYYYMMDDTHHMMSSZ format.")
    parser.add_argument("--timeout", type=int, default=30, help="Default timeout for outbound HTTP requests.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json", help="Format of the command output summary.")
    parser.add_argument("--output", help="Optional output file path for the command summary.")
    return parser.parse_args()


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "default"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_json_if_exists(path: Path) -> Any | None:
    if not path.exists():
        return None
    return load_json(path)


def load_previous_state(output_root: Path, profile_slug: str) -> dict[str, Any] | None:
    report_content_dir = output_root / "日报内容"
    state_path = report_content_dir / ".digest-state.json"
    state = load_json_if_exists(state_path)
    if isinstance(state, dict):
        return state

    legacy_latest_dir = output_root / profile_slug / "latest"
    if not legacy_latest_dir.exists():
        return None

    release_snapshot = load_json_if_exists(legacy_latest_dir / "releases.json")
    cve_snapshots: list[dict[str, Any]] = []
    for snapshot_path in sorted(legacy_latest_dir.glob("cves-*.json")):
        snapshot = load_json_if_exists(snapshot_path)
        if isinstance(snapshot, dict):
            cve_snapshots.append(snapshot)

    if release_snapshot or cve_snapshots:
        return {
            "release_snapshot": release_snapshot or {"sources": [], "new_items": [], "errors": [], "new_item_count": 0, "source_count": 0},
            "cve_snapshots": cve_snapshots,
        }
    return None


def build_timestamp(raw_value: str | None) -> tuple[str, datetime]:
    if raw_value:
        parsed = datetime.strptime(raw_value, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    else:
        parsed = datetime.now(UTC)
    return parsed.strftime("%Y%m%dT%H%M%SZ"), parsed


def local_time_parts(moment: datetime) -> tuple[str, str]:
    local_moment = moment.astimezone()
    return local_moment.strftime("%Y-%m-%d"), local_moment.strftime("%Y-%m-%d-%H-%M-%S")


def build_report_history_path(report_content_dir: Path, generated_dt: datetime) -> Path:
    day_folder, time_label = local_time_parts(generated_dt)
    day_dir = report_content_dir / day_folder
    day_dir.mkdir(parents=True, exist_ok=True)
    return day_dir / f"安全日报-{time_label}.md"


def build_release_sources(definitions: list[dict[str, Any]]) -> list[ReleaseSource]:
    sources: list[ReleaseSource] = []
    for definition in definitions:
        exclude_patterns = definition.get("exclude_patterns", [])
        if isinstance(exclude_patterns, str):
            exclude_patterns = [exclude_patterns]
        sources.append(
            ReleaseSource(
                url=definition["url"],
                vendor=definition.get("vendor"),
                product=definition.get("product"),
                mode=definition.get("mode", "auto"),
                keywords=list(definition.get("keywords", [])),
                title_pattern=definition.get("title_pattern"),
                href_pattern=definition.get("href_pattern"),
                exclude_patterns=list(exclude_patterns),
                limit=int(definition.get("limit", 10)),
            )
        )
    return sources


def collect_release_snapshot(
    *,
    release_targets: list[dict[str, Any]],
    timeout: int,
    previous_snapshot: dict[str, Any] | None,
    generated_at: str,
) -> dict[str, Any]:
    previous_urls = {
        item.get("url")
        for source in (previous_snapshot or {}).get("sources", [])
        for item in source.get("items", [])
        if item.get("url")
    }

    sources: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    new_items: list[dict[str, Any]] = []

    for source in build_release_sources(release_targets):
        try:
            collected = collect_from_source(source, timeout)
        except Exception as exc:
            errors.append({"source_url": source.url, "error": str(exc)})
            continue

        enriched_items: list[dict[str, Any]] = []
        for item in collected["items"]:
            item_copy = dict(item)
            item_copy["is_new"] = item_copy.get("url") not in previous_urls
            enriched_items.append(item_copy)
            if item_copy["is_new"]:
                new_items.append(item_copy)

        collected["items"] = enriched_items
        sources.append(collected)

    return {
        "generated_at": generated_at,
        "source_count": len(release_targets),
        "sources": sources,
        "errors": errors,
        "new_item_count": len(new_items),
        "new_items": new_items,
    }


def build_query_args(query: dict[str, Any], timeout: int) -> SimpleNamespace:
    keywords = query.get("keywords")
    if keywords is None:
        keyword_list = list(query.get("keyword", []))
    elif isinstance(keywords, str):
        keyword_list = [keywords]
    else:
        keyword_list = list(keywords)

    return SimpleNamespace(
        days=int(query.get("days", 7)),
        start_date=query.get("start_date"),
        end_date=query.get("end_date"),
        keyword=keyword_list,
        cpe_name=query.get("cpe_name"),
        severity=query.get("severity"),
        kev_only=bool(query.get("kev_only", False)),
        limit=int(query.get("limit", 25)),
        results_per_page=int(query.get("results_per_page", 200)),
        max_pages=int(query.get("max_pages", 10)),
        sleep_seconds=float(query.get("sleep_seconds", 6.0)),
        api_key_env=query.get("api_key_env", "NVD_API_KEY"),
        timeout=int(query.get("timeout", timeout)),
    )


def collect_cve_query_snapshot(
    *,
    query: dict[str, Any],
    timeout: int,
    previous_snapshot: dict[str, Any] | None,
    kev_map: dict[str, dict[str, Any]],
    generated_at: str,
) -> dict[str, Any]:
    args = build_query_args(query, timeout)
    start, end = resolve_window(args)
    records, truncated = collect_nvd_records(args, start, end)
    for record in records:
        merge_kev(record, kev_map)
    filtered = apply_filters(records, args)

    previous_ids = {item.get("cve_id") for item in (previous_snapshot or {}).get("items", []) if item.get("cve_id")}
    enriched_items: list[dict[str, Any]] = []
    new_items: list[dict[str, Any]] = []
    for item in filtered:
        item_copy = dict(item)
        item_copy["is_new"] = item_copy.get("cve_id") not in previous_ids
        enriched_items.append(item_copy)
        if item_copy["is_new"]:
            new_items.append(item_copy)

    return {
        "generated_at": generated_at,
        "query": {
            "name": query["name"],
            "keywords": args.keyword,
            "days": args.days,
            "start_date": query.get("start_date"),
            "end_date": query.get("end_date"),
            "cpe_name": args.cpe_name,
            "severity": args.severity,
            "kev_only": args.kev_only,
        },
        "window": {"start": to_iso(start), "end": to_iso(end)},
        "truncated": truncated,
        "total_collected": len(records),
        "new_item_count": len(new_items),
        "items": enriched_items,
        "new_items": new_items,
    }


def collect_cve_snapshots(
    *,
    cve_queries: list[dict[str, Any]],
    timeout: int,
    previous_cve_snapshots: dict[str, dict[str, Any]],
    generated_at: str,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    snapshots: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if not cve_queries:
        return snapshots, errors

    kev_map = fetch_kev_map(timeout)

    for query in cve_queries:
        name = query.get("name")
        if not name:
            errors.append({"query": "<missing-name>", "error": "query name is required"})
            continue

        previous_snapshot = previous_cve_snapshots.get(name)
        try:
            snapshot = collect_cve_query_snapshot(
                query=query,
                timeout=timeout,
                previous_snapshot=previous_snapshot,
                kev_map=kev_map,
                generated_at=generated_at,
            )
        except Exception as exc:
            errors.append({"query": name, "error": str(exc)})
            continue

        snapshots.append(snapshot)

    return snapshots, errors


def markdown_link(label: str, url: str | None) -> str:
    if not url:
        return label
    return f"[{label}]({url})"


def reference_lookup(reference_items: list[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    if not isinstance(reference_items, list):
        return lookup
    for item in reference_items:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if isinstance(url, str) and url:
            lookup[url] = item
    return lookup


def host_label(url: str) -> str:
    host = (urlparse(url).netloc or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host or "unknown-host"


def reference_label(url: str, detail: dict[str, Any] | None, *, category: str, index: int) -> str:
    host = host_label(url)
    tags = {
        normalize_spaces(tag).lower()
        for tag in (detail or {}).get("tags", [])
        if isinstance(tag, str) and normalize_spaces(tag)
    }

    if category == "advisory":
        if "vendor advisory" in tags:
            return f"厂商公告 ({host})"
        if "patch" in tags:
            return f"补丁说明 ({host})"
        if "release notes" in tags:
            return f"发布说明 ({host})"
        if "us government resource" in tags:
            return f"官方通报 ({host})"
        return f"官方参考 ({host})"

    if category == "poc":
        if "exploit" in tags:
            return f"公开 PoC ({host})"
        return f"PoC 参考 ({host})"

    tag_aliases = {
        "technical description": "技术说明",
        "third party advisory": "第三方公告",
        "issue tracking": "问题跟踪",
    }
    for tag, alias in tag_aliases.items():
        if tag in tags:
            return f"{alias} ({host})"
    return f"参考 {index} ({host})"


def markdown_links(
    urls: list[str],
    *,
    reference_items: list[dict[str, Any]] | None = None,
    category: str = "reference",
    max_items: int = 5,
) -> str:
    if not urls:
        return "无"
    lookup = reference_lookup(reference_items)
    items = [
        markdown_link(reference_label(url, lookup.get(url), category=category, index=index + 1), url)
        for index, url in enumerate(urls[:max_items])
    ]
    return " | ".join(items)


def compact_text(value: str | None, *, max_chars: int = 420) -> str:
    text = normalize_spaces(value)
    if not text:
        return "无"
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def render_digest_markdown(
    *,
    profile_name: str,
    generated_at: str,
    release_snapshot: dict[str, Any],
    cve_snapshots: list[dict[str, Any]],
    errors: list[dict[str, str]],
    report_config: dict[str, Any],
) -> str:
    title = report_config.get("title") or f"Security Digest - {profile_name}"
    max_release_items = int(report_config.get("max_release_items", 15))
    max_cve_items = int(report_config.get("max_cve_items", 15))

    total_release_items = sum(len(source.get("items", [])) for source in release_snapshot["sources"])
    total_cve_items = sum(len(snapshot.get("items", [])) for snapshot in cve_snapshots)
    total_new_cves = sum(snapshot.get("new_item_count", 0) for snapshot in cve_snapshots)

    lines = [
        f"# {title}",
        "",
        f"生成时间: {generated_at}",
        f"配置名: {profile_name}",
        "",
        "## 今日概览",
        f"- 巡检发布源数量: {release_snapshot['source_count']}",
        f"- 收集到的发布项数量: {total_release_items}",
        f"- 新发布/新公告数量: {release_snapshot['new_item_count']}",
        f"- 漏洞查询数量: {len(cve_snapshots)}",
        f"- 收集到的漏洞条目数量: {total_cve_items}",
        f"- 新漏洞条目数量: {total_new_cves}",
        "",
        "## 厂商发布动态",
    ]

    new_release_items = release_snapshot["new_items"][:max_release_items]
    if new_release_items:
        for item in new_release_items:
            label = " / ".join(part for part in (item.get("vendor"), item.get("product")) if part) or item.get("source_url") or "unknown-source"
            published = item.get("published") or "unknown-date"
            lines.append(f"### {item['title']}")
            lines.append(f"- 来源: {label}")
            lines.append(f"- 发布时间: {published}")
            lines.append(f"- 链接: {markdown_link('Official Link', item['url'])}")
            lines.append(f"- 摘要: {compact_text(item.get('summary'), max_chars=260)}")
            lines.append("")
    else:
        lines.append("- 未发现新的发布项或公告。")

    lines.extend(["", "## 漏洞日报"])
    had_new_cves = False
    for snapshot in cve_snapshots:
        query_name = snapshot["query"]["name"]
        lines.append(f"### {query_name}")
        query_new_items = snapshot["new_items"][:max_cve_items]
        if query_new_items:
            had_new_cves = True
            for item in query_new_items:
                severity = item.get("severity") or "UNKNOWN"
                kev_flag = "KEV" if item.get("kev") else "NVD"
                published = item.get("published") or "unknown-date"
                affected = item.get("affected_versions") or []
                advisory_urls = item.get("advisory_urls") or []
                poc_urls = item.get("public_poc_urls") or []
                reference_items = item.get("reference_details") or []
                other_refs = [
                    ref
                    for ref in (item.get("references") or [])
                    if ref not in advisory_urls and ref not in poc_urls and ref != item.get("nvd_url")
                ]
                score = item.get("score")
                severity_line = severity if score in (None, "") else f"{severity} ({score})"

                lines.append(f"#### {item['cve_id']}")
                lines.append(f"- 严重程度: {severity_line} | 来源标记: {kev_flag}")
                lines.append(f"- 发布时间: {published}")
                lines.append(f"- 详情链接: {markdown_link('NVD', item['nvd_url'])}")
                if item.get("kev"):
                    lines.append(f"- KEV 状态: 是 | 加入日期: {item.get('kev_date_added') or '未知'}")
                else:
                    lines.append("- KEV 状态: 否")
                lines.append(f"- 漏洞介绍: {compact_text(item.get('summary'), max_chars=420)}")
                lines.append(f"- 目标版本: {', '.join(affected[:8]) if affected else '未从官方结构化数据中解析到明确受影响版本'}")
                lines.append(f"- 利用原理: {compact_text(item.get('mechanism_summary') or item.get('summary'), max_chars=420)}")
                lines.append(f"- 厂商/官方参考: {markdown_links(advisory_urls, reference_items=reference_items, category='advisory')}")
                lines.append(f"- 已公开 PoC: {markdown_links(poc_urls, reference_items=reference_items, category='poc')}")
                lines.append(f"- 其他参考: {markdown_links(other_refs, reference_items=reference_items, category='reference')}")
                lines.append("")
        else:
            lines.append("- 未发现新的漏洞条目。")
        lines.append("")

    if not cve_snapshots:
        lines.append("- 未配置漏洞查询。")
        lines.append("")
    elif not had_new_cves:
        pass

    lines.append("## 运行情况")
    if errors:
        for error in errors:
            scope = error.get("source_url") or error.get("query") or "unknown"
            lines.append(f"- {scope}: {error['error']}")
    else:
        lines.append("- 本次运行无采集错误。")

    return "\n".join(lines).strip() + "\n"


def render_summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Digest Run Summary",
        "",
        f"Generated at: {summary['generated_at']}",
        f"Profile: {summary['profile_name']}",
        f"Report: {summary['report_path']}",
        f"State: {summary['state_path']}",
    ]
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    args = parse_args()
    try:
        config_path = Path(args.config)
        output_root = Path(args.output_root)
        config = load_json(config_path)

        profile_name = config.get("profile_name", config_path.stem)
        _, generated_dt = build_timestamp(args.timestamp)
        generated_at = to_iso(generated_dt)

        profile_slug = slugify(profile_name)
        output_root.mkdir(parents=True, exist_ok=True)
        report_content_dir = output_root / "日报内容"
        report_content_dir.mkdir(parents=True, exist_ok=True)

        release_targets = list(config.get("release_targets", []))
        cve_queries = list(config.get("cve_queries", []))
        if not release_targets and not cve_queries:
            raise ValueError("config must include release_targets or cve_queries")

        previous_state = load_previous_state(output_root, profile_slug) or {}
        previous_release_snapshot = previous_state.get("release_snapshot")
        previous_cve_snapshots = {
            snapshot.get("query", {}).get("name"): snapshot
            for snapshot in previous_state.get("cve_snapshots", [])
            if isinstance(snapshot, dict) and snapshot.get("query", {}).get("name")
        }
        release_snapshot = collect_release_snapshot(
            release_targets=release_targets,
            timeout=args.timeout,
            previous_snapshot=previous_release_snapshot,
            generated_at=generated_at,
        )

        cve_snapshots, cve_errors = collect_cve_snapshots(
            cve_queries=cve_queries,
            timeout=args.timeout,
            previous_cve_snapshots=previous_cve_snapshots,
            generated_at=generated_at,
        )

        all_errors = list(release_snapshot["errors"]) + list(cve_errors)

        report_markdown = render_digest_markdown(
            profile_name=profile_name,
            generated_at=generated_at,
            release_snapshot=release_snapshot,
            cve_snapshots=cve_snapshots,
            errors=all_errors,
            report_config=dict(config.get("report", {})),
        )

        report_path = build_report_history_path(report_content_dir, generated_dt)
        report_path.write_text(report_markdown, encoding="utf-8")
        (report_content_dir / "latest.md").write_text(report_markdown, encoding="utf-8")

        state_path = report_content_dir / ".digest-state.json"
        write_json(
            state_path,
            {
                "generated_at": generated_at,
                "profile_name": profile_name,
                "release_snapshot": release_snapshot,
                "cve_snapshots": cve_snapshots,
            },
        )

        summary = {
            "generated_at": generated_at,
            "profile_name": profile_name,
            "profile_root": str(output_root),
            "report_path": str(report_path),
            "state_path": str(state_path),
            "release_new_item_count": release_snapshot["new_item_count"],
            "cve_new_item_count": sum(snapshot["new_item_count"] for snapshot in cve_snapshots),
            "error_count": len(all_errors),
        }

        if args.format == "json":
            output = json.dumps(summary, indent=2, ensure_ascii=False)
        else:
            output = render_summary_markdown(summary)
        write_text_output(output, args.output)
        return 0
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
