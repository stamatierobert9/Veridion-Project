"""
DNS signals - very cheap to collect (one UDP query, not a full HTTP
request) and surprisingly rich:

  - CNAMEs reveal managed hosting: e.g. a CNAME to "shops.myshopify.com" =
    Shopify, to "cname.vercel-dns.com" = Vercel, to "ghs.googlehosted.com" =
    Google Sites.
  - MX records show the email provider: "aspmx.l.google.com" = Google
    Workspace, "*.protection.outlook.com" = Microsoft 365.
  - TXT records often contain domain verifications for third-party
    services: google-site-verification=..., facebook-domain-verification=...,
    MS=..., stripe-verification=..., v=spf1 include:sendgrid.net ...

These signals complement the ones from HTML/headers - many technologies
like "email provider" or "hosting platform" don't show up in the web page
at all, but are clearly visible in DNS.
"""
from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.exception

from src import config
from src.models import DnsRecords

logger = logging.getLogger(__name__)


async def _query(resolver: dns.asyncresolver.Resolver, domain: str, rtype: str) -> list[str]:
    try:
        answer = await resolver.resolve(domain, rtype, lifetime=config.DNS_TIMEOUT_SECONDS)
        return [r.to_text().strip('"') for r in answer]
    except (dns.exception.DNSException, Exception):  # noqa: BLE001 - a missing record is normal, not an error
        return []


async def fetch_dns(domain: str) -> DnsRecords:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = config.DNS_TIMEOUT_SECONDS

    a, aaaa, cname, mx, txt, ns = await asyncio.gather(
        _query(resolver, domain, "A"),
        _query(resolver, domain, "AAAA"),
        _query(resolver, domain, "CNAME"),
        _query(resolver, domain, "MX"),
        _query(resolver, domain, "TXT"),
        _query(resolver, domain, "NS"),
    )
    return DnsRecords(a=a, aaaa=aaaa, cname=cname, mx=mx, txt=txt, ns=ns)


async def fetch_all_dns(domains: list[str]) -> dict[str, DnsRecords]:
    semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_REQUESTS)

    async def bound(domain: str) -> tuple[str, DnsRecords]:
        async with semaphore:
            return domain, await fetch_dns(domain)

    done = 0
    results: dict[str, DnsRecords] = {}
    for coro in asyncio.as_completed([bound(d) for d in domains]):
        domain, records = await coro
        results[domain] = records
        done += 1
        if done % 50 == 0 or done == len(domains):
            logger.info("DNS: %d/%d domains processed", done, len(domains))

    return results
