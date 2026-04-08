#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urldefrag, urljoin

from common import fetch_text, normalize_spaces, parse_datetime, to_iso, write_text_output

DEFAULT_HINTS = (
    "release",
    "releases",
    "changelog",
    "security",
    "advisory",
    "update",
    "stable",
)


@dataclass
class ReleaseSource:
    url: str
    vendor: str | None = None
    product: str | None = None
    mode: str = "auto"
    keywords: list[str] = field(default_factory=list)
    title_pattern: str | None = None
    href_pattern: str | None = None
    exclude_patterns: list[str] = field(default_factory=list)
    limit: int = 10


class ReleasePageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.alternate_feeds: list[str] = []
        self.anchors: list[dict[str, str]] = []
        self._anchor_href: str | None = None
        self._anchor_text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key: value or "" for key, value in attrs}

        if tag == "link":
            rel = attr_map.get("rel", "").lower()
            href = attr_map.get("href", "")
            content_type = attr_map.get("type", "").lower()
            if href and "alternate" in rel and ("rss" in content_type or "atom" in content_type or "xml" in content_type):
                self.alternate_feeds.append(href)
            return

        if tag == "a":
            href = attr_map.get("href", "")
            if href:
                self._anchor_href = href
                self._anchor_text_parts = []

    def handle_data(self, data: str) -> None:
        if self._anchor_href is not None:
            self._anchor_text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._anchor_href is not None:
            text = normalize_spaces(" ".join(self._anchor_text_parts))
            self.anchors.append({"href": self._anchor_href, "text": text})
            self._anchor_href = None
            self._anchor_text_parts = []


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def direct_children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(element) if local_name(child.tag) == name]


def direct_text(element: ET.Element, names: tuple[str, ...]) -> str | None:
    for child in list(element):
        if local_name(child.tag) in names:
            text = normalize_spaces("".join(child.itertext()))
            if text:
                return text
    return None


def atom_link(entry: ET.Element) -> str | None:
    for child in list(entry):
        if local_name(child.tag) != "link":
            continue
        href = child.attrib.get("href")
        rel = child.attrib.get("rel", "alternate")
        if href and rel in {"alternate", ""}:
            return href
    return None


def infer_date(*values: str | None) -> datetime | None:
    for value in values:
        parsed = parse_datetime(value)
        if parsed is not None:
            return parsed

        if not value:
            continue

        match = re.search(r"(?P<year>20\d{2}|19\d{2})[-/](?P<month>\d{1,2})[-/](?P<day>\d{1,2})", value)
        if not match:
            continue

        try:
            return datetime(
                int(match.group("year")),
                int(match.group("month")),
                int(match.group("day")),
                tzinfo=UTC,
            )
        except ValueError:
            continue
    return None


def matches_filters(item: dict[str, Any], source: ReleaseSource) -> tuple[bool, list[str]]:
    title = normalize_spaces(item.get("title"))
    url = normalize_spaces(item.get("url"))
    summary = normalize_spaces(item.get("summary"))
    haystack = f"{title} {url} {summary}".lower()

    matched_keywords: list[str] = []
    if source.keywords:
        matched_keywords = [keyword for keyword in source.keywords if keyword.lower() in haystack]
        if not matched_keywords:
            return False, []
    else:
        matched_keywords = [hint for hint in DEFAULT_HINTS if hint in haystack]
        if not matched_keywords:
            return False, []

    if source.title_pattern and not re.search(source.title_pattern, title, re.IGNORECASE):
        return False, []

    if source.href_pattern and not re.search(source.href_pattern, url, re.IGNORECASE):
        return False, []

    for pattern in source.exclude_patterns:
        if re.search(pattern, haystack, re.IGNORECASE):
            return False, []

    return True, matched_keywords


def parse_feed_items(xml_text: str, base_url: str) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_text)
    root_name = local_name(root.tag)
    items: list[dict[str, Any]] = []

    if root_name == "rss":
        channels = direct_children(root, "channel")
        candidates = direct_children(channels[0], "item") if channels else []
    elif root_name == "feed":
        candidates = direct_children(root, "entry")
    else:
        candidates = direct_children(root, "item")

    for candidate in candidates:
        if root_name == "feed":
            link = atom_link(candidate)
            published = direct_text(candidate, ("published", "updated", "modified"))
            summary = direct_text(candidate, ("summary", "content"))
        else:
            link = direct_text(candidate, ("link",))
            published = direct_text(candidate, ("pubdate", "published", "updated", "modified", "date"))
            summary = direct_text(candidate, ("description", "summary", "content"))

        title = direct_text(candidate, ("title",)) or link or "Untitled release entry"
        item_url = urljoin(base_url, link) if link else None
        if not item_url:
            continue

        items.append(
            {
                "title": title,
                "url": item_url,
                "published": to_iso(infer_date(published, title, item_url)),
                "summary": summary,
                "collection_mode": "feed",
            }
        )

    return items


def parse_html_items(html_text: str, base_url: str) -> tuple[list[str], list[dict[str, Any]]]:
    parser = ReleasePageParser()
    parser.feed(html_text)

    items: list[dict[str, Any]] = []
    for anchor in parser.anchors:
        href = anchor["href"].strip()
        if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
            continue

        resolved_url = urldefrag(urljoin(base_url, href)).url
        title = normalize_spaces(anchor["text"]) or resolved_url
        if not title:
            continue

        items.append(
            {
                "title": title,
                "url": resolved_url,
                "published": to_iso(infer_date(title, resolved_url)),
                "summary": None,
                "collection_mode": "html",
            }
        )

    return parser.alternate_feeds, items


def dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for item in items:
        url = item.get("url")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        deduped.append(item)
    return deduped


def collect_from_source(source: ReleaseSource, timeout: int) -> dict[str, Any]:
    text, response = fetch_text(source.url, timeout=timeout)
    content_type = response.headers.get("content-type", "").lower()
    collected_at = to_iso(datetime.now(UTC))
    items: list[dict[str, Any]] = []
    feed_url: str | None = None

    try_feed = source.mode == "feed" or (source.mode == "auto" and "xml" in content_type)
    if try_feed:
        try:
            items = parse_feed_items(text, response.url)
        except ET.ParseError:
            items = []

    if source.mode == "html":
        _, items = parse_html_items(text, response.url)
    elif source.mode == "auto" and not items:
        alternate_feeds, html_items = parse_html_items(text, response.url)
        if alternate_feeds:
            feed_url = urljoin(response.url, alternate_feeds[0])
            feed_text, feed_response = fetch_text(feed_url, timeout=timeout)
            try:
                items = parse_feed_items(feed_text, feed_response.url)
            except ET.ParseError:
                items = html_items
        else:
            items = html_items

    filtered: list[dict[str, Any]] = []
    for item in dedupe_items(items):
        matched, matched_keywords = matches_filters(item, source)
        if not matched:
            continue
        filtered.append(
            {
                "vendor": source.vendor,
                "product": source.product,
                "source_url": source.url,
                "feed_url": feed_url,
                "collection_mode": item["collection_mode"],
                "title": item["title"],
                "url": item["url"],
                "published": item.get("published"),
                "summary": item.get("summary"),
                "matched_keywords": matched_keywords,
                "collected_at": collected_at,
            }
        )

    filtered.sort(key=lambda item: (item["published"] is not None, item["published"] or "", item["title"]), reverse=True)
    if source.limit > 0:
        filtered = filtered[: source.limit]

    return {
        "vendor": source.vendor,
        "product": source.product,
        "source_url": source.url,
        "resolved_source_url": response.url,
        "items": filtered,
    }


def load_sources_from_config(path: str) -> list[ReleaseSource]:
    raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(raw, list):
        source_definitions = raw
    elif isinstance(raw, dict) and isinstance(raw.get("targets"), list):
        source_definitions = raw["targets"]
    else:
        raise ValueError("config must be a JSON array or an object with a targets array")

    sources: list[ReleaseSource] = []
    for definition in source_definitions:
        if not isinstance(definition, dict):
            raise ValueError("each target in config must be an object")
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect recent release or advisory items from official vendor pages.")
    parser.add_argument("--config", help="Path to a JSON config file with one or more release sources.")
    parser.add_argument("--url", help="Single vendor release or advisory page URL.")
    parser.add_argument("--vendor", help="Vendor label for single-source mode.")
    parser.add_argument("--product", help="Product label for single-source mode.")
    parser.add_argument("--mode", choices=("auto", "feed", "html"), default="auto")
    parser.add_argument("--keyword", action="append", default=[], help="Keyword used to filter release entries.")
    parser.add_argument("--title-pattern", help="Regex that must match the release title.")
    parser.add_argument("--href-pattern", help="Regex that must match the release URL.")
    parser.add_argument("--exclude-pattern", action="append", default=[], help="Regex used to drop irrelevant entries.")
    parser.add_argument("--limit", type=int, default=10, help="Maximum items to keep per source.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", help="Optional output file path.")
    args = parser.parse_args()

    if not args.config and not args.url:
        parser.error("pass either --config or --url")
    return args


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Vendor Release Collection",
        "",
        f"Generated at: {payload['generated_at']}",
        "",
    ]
    for source in payload["sources"]:
        label = " / ".join(part for part in (source.get("vendor"), source.get("product")) if part) or source["source_url"]
        lines.append(f"## {label}")
        lines.append(f"Source: {source['resolved_source_url']}")
        if not source["items"]:
            lines.append("No matching entries found.")
            lines.append("")
            continue
        for item in source["items"]:
            published = item.get("published") or "unknown-date"
            lines.append(f"- {published} | {item['title']} | {item['url']}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    args = parse_args()
    try:
        if args.config:
            sources = load_sources_from_config(args.config)
        else:
            sources = [
                ReleaseSource(
                    url=args.url,
                    vendor=args.vendor,
                    product=args.product,
                    mode=args.mode,
                    keywords=args.keyword,
                    title_pattern=args.title_pattern,
                    href_pattern=args.href_pattern,
                    exclude_patterns=args.exclude_pattern,
                    limit=args.limit,
                )
            ]

        payload = {
            "generated_at": to_iso(datetime.now(UTC)),
            "sources": [collect_from_source(source, args.timeout) for source in sources],
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
