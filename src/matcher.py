"""
=========================================================================
 AICI E CREIERUL PROIECTULUI - scrie tu logica asta, e partea evaluata.
=========================================================================

Rolul acestui modul: primeste un RawSite (din crawler.py + dns_lookup.py)
si baza de Technology (din fingerprints.py) si intoarce o lista de
Detection, fiecare cu dovezi concrete (Evidence).

Mai jos ai scheletul + ce trebuie sa faca fiecare functie. Am lasat
intentionat neimplementata partea de decizie - completeaz-o tu, ganditor
cu ganditor, si noteaza in README ce alegeri ai facut si de ce (asta e
exact ce vor sa vada la Veridion).

------------------------------------------------------------------------
Ce trebuie sa faca `detect_technologies(site, technologies)`:

1. Pentru fiecare Technology din baza, verifica pe rand fiecare tip de
   semnal disponibil in `site`:
     - site.headers      vs tech.headers      (regex pe valoarea headerului)
     - site.cookies      vs tech.cookies      (regex pe valoarea cookie-ului)
     - site.html         vs tech.meta         (trebuie sa extragi intai
                                                 tag-urile <meta name=X content=Y>
                                                 din HTML - vezi hint mai jos)
     - site.html         vs tech.html         (regex direct pe tot HTML-ul)
     - site.html         vs tech.script_src   (regex pe atributele src= ale <script>)
     - site.dns.cname/mx/txt vs tech.dns      (regex pe recordurile DNS)

2. Cand un pattern face match, construieste un Evidence cu:
     - signal_type: ce tip de semnal a fost ("header", "cookie", "meta", "html", "script_src", "dns_cname"...)
     - pattern: regex-ul (ca string) care a facut match
     - matched_value: fragmentul REAL din raspuns care a facut match (trunchiat la ~150 caractere -
       nu tot HTML-ul! Asta e "dovada" ceruta explicit in task, trebuie sa fie citibila de un om)

3. Aduna toate Evidence-urile pentru o tehnologie si decide un `confidence`
   intre 0 si 1. Intrebari la care trebuie sa raspunzi tu (si sa le pui in README):
     - un singur match pe `html` (regex generic) conteaza la fel de mult ca
       un match pe `headers` (mult mai specific si greu de falsificat)?
     - multiple dovezi independente pentru aceeasi tehnologie ar trebui sa
       creasca increderea?
     - foloseati `directives.get("confidence")` din regulile Wappalyzer
       (unele reguli au deja un scor sugerat, 0-100) ca punct de plecare?

4. (Optional, dar interesant de discutat in README) `implies`: multe
   tehnologii au camp "implies" (ex: WordPress implies PHP + MySQL).
   Le adaugi automat cu incredere mai mica? Sau le ignori ca sa nu umfli
   artificial numarul de tehnologii "gasite"? Nu exista un raspuns corect -
   conteaza sa argumentezi alegerea.

5. Dedup: doua reguli diferite ale aceleiasi tehnologii care fac match nu
   inseamna doua tehnologii - raman un singur Detection cu mai multe Evidence.

------------------------------------------------------------------------
Hint pt parsing <meta> din HTML (fara sa aduci un parser HTML complet doar
pt asta - desi poti folosi si `html.parser`/`lxml` daca preferi):

    import re
    META_RE = re.compile(
        r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']',
        re.IGNORECASE,
    )
    for name, content in META_RE.findall(site.html):
        ...

Hint pt extras <script src="...">:

    SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

------------------------------------------------------------------------
"""
from __future__ import annotations

from src.fingerprints import Technology
from src.models import Detection, RawSite


def detect_technologies(site: RawSite, technologies: dict[str, Technology]) -> list[Detection]:
    """
    TODO(Robert): implementeaza logica descrisa mai sus.

    Ramane deliberat gol / minimal - vezi docstring-ul modulului.
    Placeholder-ul de mai jos NU face detectie reala, doar iti arata forma
    asteptata a output-ului, ca sa poti rula pipeline.py end-to-end de la
    inceput si sa vezi ca totul se leaga (crawler -> matcher -> output).
    """
    if site.error:
        return []

    detections: list[Detection] = []

    # --- exemplu minimal, doar pe headers, ca sa vezi ca pipeline-ul merge ---
    for name, tech in technologies.items():
        for rule in tech.headers:
            header_value = site.headers.get((rule.key or "").lower())
            if header_value and rule.pattern.search(header_value):
                detections.append(
                    Detection(
                        technology=name,
                        categories=tech.categories,
                        confidence=0.5,  # TODO: calculeaza un scor real
                        evidence=[
                            # TODO: importa Evidence din src.models si construieste-l aici
                        ],
                    )
                )
                break  # nu mai continua cu alte header-uri pt aceeasi tehnologie

    # TODO: adauga cookies, meta, html, script_src, dns
    # TODO: dedup + calcul confidence agregat
    # TODO: decide ce faci cu `implies`

    return detections
