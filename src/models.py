"""
Shared data structures passed between crawler -> matcher -> output.

Keeping them separate from the logic helps with two things:
  1. matcher.py can be tested with RawSite objects built by hand in
     tests/, without making real HTTP requests.
  2. the raw crawl can be cached and the matcher re-run many times (e.g.
     after adding new fingerprints) by (de)serializing RawSite, without
     hitting the network again.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DnsRecords:
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)


@dataclass
class RawSite:
    """Everything collected about a domain, before detection."""

    domain: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    headers: dict[str, str] = field(default_factory=dict)     # lowercased keys
    html: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    dns: DnsRecords = field(default_factory=DnsRecords)
    error: Optional[str] = None                                # failure reason, if the fetch failed
    fetch_ms: Optional[int] = None
    # DECISION (how to get closer to 477): many technologies don't show up
    # on the homepage (reCAPTCHA on /contact, ecommerce on /shop, comments
    # on /blog, etc.). Instead of a headless browser (high cost, low ROI
    # measured on this dataset - see README), we crawl a few extra internal
    # pages from the same domain and keep them here.
    extra_pages: list["RawSite"] = field(default_factory=list)


@dataclass
class Evidence:
    """A single concrete piece of proof for a detection (explicit task requirement)."""

    signal_type: str      # "header" | "html" | "script_src" | "cookie" | "meta" | "dns_cname" | "dns_mx" | "dns_txt" | "dns_ns" | "dom" | "implied"
    pattern: str           # the regex / key that matched
    matched_value: str     # the actual fragment of the response that triggered the match (truncated)


@dataclass
class Detection:
    technology: str
    categories: list[str]
    confidence: float          # 0..1, see matcher.py for how it's computed
    evidence: list[Evidence] = field(default_factory=list)
    version: Optional[str] = None
