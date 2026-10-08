"""
Orchestrates the whole flow: read the domains -> crawl (HTTP + DNS in
parallel) -> run the matcher -> write the output.

Split into clear stages so each piece can be run/tested independently
(e.g. re-run only the matcher after changing a rule, without re-crawling
the 200 domains every time - see `--from-cache` in scripts/run.py).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import asdict

import pandas as pd

from src import config
from src.crawler import fetch_all
from src.dns_lookup import fetch_all_dns
from src.fingerprints import load_technologies
from src.matcher import detect_technologies
from src.models import DnsRecords, RawSite
from src.output import write_results

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def load_domains() -> list[str]:
    df = pd.read_csv(config.DOMAINS_CSV)
    return df["root_domain"].dropna().astype(str).tolist()


def _cache_path(domain: str) -> "config.Path":
    safe = domain.replace("/", "_")
    return config.RAW_SNAPSHOTS_DIR / f"{safe}.json"


def save_raw_snapshots(sites: list[RawSite]) -> None:
    config.RAW_SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    for site in sites:
        with open(_cache_path(site.domain), "w", encoding="utf-8") as f:
            json.dump(asdict(site), f, ensure_ascii=False)


def _dict_to_rawsite(raw: dict) -> RawSite:
    """Recursively rebuilds a RawSite from a dict (json.load) - handles
    DnsRecords and extra_pages (nested lists of RawSite) too, not just the
    top-level fields."""
    raw = dict(raw)
    raw["dns"] = DnsRecords(**raw.get("dns", {}))
    raw["extra_pages"] = [_dict_to_rawsite(p) for p in raw.get("extra_pages", [])]
    return RawSite(**raw)


def load_raw_snapshots(domains: list[str]) -> list[RawSite]:
    sites = []
    for domain in domains:
        path = _cache_path(domain)
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        sites.append(_dict_to_rawsite(raw))
    return sites


async def crawl_stage(domains: list[str]) -> list[RawSite]:
    t0 = time.monotonic()
    logger.info("crawling %d domains (HTTP + DNS, concurrently)...", len(domains))

    http_task = fetch_all(domains)
    dns_task = fetch_all_dns(domains)
    sites, dns_map = await asyncio.gather(http_task, dns_task)

    for site in sites:
        site.dns = dns_map.get(site.domain, DnsRecords())

    failed = [s for s in sites if s.error]
    logger.info("crawl done in %.1fs - %d/%d domains failed", time.monotonic() - t0, len(failed), len(domains))
    for s in failed[:20]:
        logger.info("  failed: %-40s %s", s.domain, s.error)
    if len(failed) > 20:
        logger.info("  ... and %d more", len(failed) - 20)

    extra_fetched = sum(len(s.extra_pages) for s in sites)
    logger.info("extra internal pages crawled: %d (on top of the %d homepages)", extra_fetched, len(domains))

    return sites


def detect_stage(sites: list[RawSite]) -> dict[str, list]:
    logger.info("loading the fingerprint database...")
    technologies = load_technologies()
    logger.info("%d technologies in the database", len(technologies))

    # DECISION: matching is CPU-bound (especially the CSS selectors for the
    # "dom" rules - soup.select() is a tree walk per selector per page, and
    # there are ~1800 selectors * up to ~600 pages in total with the extra
    # internal pages). Without logging here, a run that spends a few
    # minutes in this stage looks identical to one that's stuck - which is
    # exactly what happened to me. Simple progress logging, like the crawl.
    total = len(sites)
    start = time.monotonic()
    results = {}
    for i, site in enumerate(sites, start=1):
        results[site.domain] = detect_technologies(site, technologies)
        if i % 25 == 0 or i == total:
            elapsed = time.monotonic() - start
            logger.info("matching: %d/%d domains processed (%.1fs)", i, total, elapsed)
    return results


async def run(use_cache: bool = False) -> None:
    domains = load_domains()
    logger.info("%d domains to process", len(domains))

    if use_cache:
        logger.info("using previously saved raw snapshots (no re-crawl)")
        sites = load_raw_snapshots(domains)
    else:
        sites = await crawl_stage(domains)
        save_raw_snapshots(sites)

    results = detect_stage(sites)
    write_results(results)
