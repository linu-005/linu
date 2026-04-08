#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT = 30
USER_AGENT = "CodexProductSecurityLabReview/1.0"


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes


def fetch_bytes(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> HttpResponse:
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, application/xml, text/xml, text/html;q=0.9, */*;q=0.8",
    }
    if headers:
        request_headers.update(headers)

    request = Request(url, headers=request_headers)
    with urlopen(request, timeout=timeout) as response:
        body = response.read()
        normalized_headers = {key.lower(): value for key, value in response.headers.items()}
        status = getattr(response, "status", response.getcode())
        return HttpResponse(
            url=response.geturl(),
            status=status,
            headers=normalized_headers,
            body=body,
        )


def _content_charset(content_type: str | None) -> str:
    if not content_type:
        return "utf-8"

    match = re.search(r"charset=([A-Za-z0-9._-]+)", content_type, re.IGNORECASE)
    if match:
        return match.group(1)
    return "utf-8"


def fetch_text(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[str, HttpResponse]:
    response = fetch_bytes(url, headers=headers, timeout=timeout)
    charset = _content_charset(response.headers.get("content-type"))
    return response.body.decode(charset, errors="replace"), response


def fetch_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[Any, HttpResponse]:
    text, response = fetch_text(url, headers=headers, timeout=timeout)
    return json.loads(text), response


def normalize_spaces(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", value).strip()


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    candidate = value.strip()
    if not candidate:
        return None

    try:
        return datetime.fromisoformat(candidate.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%b %d, %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(candidate, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue

    try:
        parsed = parsedate_to_datetime(candidate)
    except (TypeError, ValueError, IndexError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def to_zulu(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def write_text_output(content: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
        return
    print(content)
