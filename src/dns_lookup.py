"""
Semnale DNS - foarte ieftine de colectat (un query UDP, nu un request HTTP
complet) si surprinzator de bogate:

  - CNAME-uri dezvaluie hosting-ul gestionat: ex un CNAME catre
    "shops.myshopify.com" = Shopify, catre "cname.vercel-dns.com" = Vercel,
    catre "ghs.googlehosted.com" = Google Sites.
  - Recordurile MX arata furnizorul de email: "aspmx.l.google.com" = Google
    Workspace, "*.protection.outlook.com" = Microsoft 365.
  - TXT records contin adesea verificari de domeniu pentru terte servicii:
    google-site-verification=..., facebook-domain-verification=...,
    MS=..., stripe-verification=..., v=spf1 include:sendgrid.net ...

Aceste semnale sunt complementare celor din HTML/headers - multe tehnologii
de genul "furnizor de email" sau "platforma de hosting" nu apar deloc in
pagina web, dar apar clar in DNS.
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
    except (dns.exception.DNSException, Exception):  # noqa: BLE001 - lipsa unui record e normala, nu e o eroare
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

    pairs = await asyncio.gather(*(bound(d) for d in domains))
    return dict(pairs)
