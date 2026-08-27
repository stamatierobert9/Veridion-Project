"""
Orchestreaza tot fluxul: citeste domeniile -> crawleaza (HTTP + DNS in
paralel) -> ruleaza matcher-ul -> scrie output-ul.

Separat in pasi clari ca sa poti rula/testa fiecare bucata independent
(ex: sa re-rulezi doar matcher-ul dupa ce modifici o regula, fara sa
re-crawlezi cele 200 de domenii de fiecare data - vezi `--from-cache`
in scripts/run.py).
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
    """Reconstruieste recursiv un RawSite dintr-un dict (json.load) - are
    grija si de DnsRecords si de extra_pages (liste de RawSite imbricate),
    nu doar de campurile de nivelul 1."""
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
    logger.info("crawling %d domenii (HTTP + DNS, concurent)...", len(domains))

    http_task = fetch_all(domains)
    dns_task = fetch_all_dns(domains)
    sites, dns_map = await asyncio.gather(http_task, dns_task)

    for site in sites:
        site.dns = dns_map.get(site.domain, DnsRecords())

    failed = [s for s in sites if s.error]
    logger.info("crawl gata in %.1fs - %d/%d domenii cu eroare", time.monotonic() - t0, len(failed), len(domains))
    for s in failed[:20]:
        logger.info("  esuat: %-40s %s", s.domain, s.error)
    if len(failed) > 20:
        logger.info("  ... si inca %d", len(failed) - 20)

    extra_fetched = sum(len(s.extra_pages) for s in sites)
    logger.info("pagini interne suplimentare crawlite: %d (peste cele %d homepage-uri)", extra_fetched, len(domains))

    return sites


def detect_stage(sites: list[RawSite]) -> dict[str, list]:
    logger.info("incarc baza de fingerprint-uri...")
    technologies = load_technologies()
    logger.info("%d tehnologii in baza de date", len(technologies))

    results = {}
    for site in sites:
        results[site.domain] = detect_technologies(site, technologies)
    return results


async def run(use_cache: bool = False) -> None:
    domains = load_domains()
    logger.info("%d domenii de procesat", len(domains))

    if use_cache:
        logger.info("folosesc snapshot-urile brute salvate anterior (fara re-crawl)")
        sites = load_raw_snapshots(domains)
    else:
        sites = await crawl_stage(domains)
        save_raw_snapshots(sites)

    results = detect_stage(sites)
    write_results(results)
