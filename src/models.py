"""
Structuri de date comune, folosite intre crawler -> matcher -> output.

Tinerea lor separate de logica ajuta la doua lucruri:
  1. matcher.py poate fi testat cu obiecte RawSite construite manual in
     tests/, fara sa faci request-uri HTTP reale.
  2. daca vrei sa cachezi crawl-ul brut si sa rulezi matcher-ul de mai
     multe ori (ex: dupa ce mai adaugi fingerprint-uri), poti (de)serializa
     RawSite fara sa mai lovesti reteaua.
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
    """Tot ce am reusit sa culegem despre un domeniu, inainte de detectie."""

    domain: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    headers: dict[str, str] = field(default_factory=dict)     # lowercased keys
    html: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    dns: DnsRecords = field(default_factory=DnsRecords)
    error: Optional[str] = None                                # motivul esecului, daca a esuat
    fetch_ms: Optional[int] = None
    # DECIZIE (raspuns la "cum aducem numarul mai aproape de 477"): multe
    # tehnologii nu apar pe homepage (recaptcha pe /contact, ecommerce pe
    # /shop, comentarii pe /blog etc.) - in loc de headless browser (cost
    # mare, ROI mic masurat pe acest set - vezi README), crawlem cateva
    # pagini interne suplimentare de pe acelasi domeniu si le pastram aici.
    extra_pages: list["RawSite"] = field(default_factory=list)


@dataclass
class Evidence:
    """O singura dovada concreta pentru o detectie (cerinta explicita din task)."""

    signal_type: str      # "header" | "html" | "script_src" | "cookie" | "meta" | "dns_cname" | "dns_mx" | "dns_txt" | "css"
    pattern: str           # regex-ul / cheia care a facut match
    matched_value: str     # fragmentul real din raspuns care a declansat match-ul (trunchiat)


@dataclass
class Detection:
    technology: str
    categories: list[str]
    confidence: float          # 0..1, vezi matcher.py pentru cum se calculeaza
    evidence: list[Evidence] = field(default_factory=list)
    version: Optional[str] = None
