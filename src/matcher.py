"""
Motorul de detectie: primeste un RawSite si baza de Technology si intoarce
o lista de Detection, fiecare cu dovezi concrete.

IMPORTANT (citeste asta): am scris eu implementarea de mai jos ca sa avem
un draft de la care sa pornim, dar deciziile de fond sunt marcate explicit
cu "# DECIZIE:" - sunt alegerile pe care le poti schimba/argumenta diferit
in README (scorul de incredere per tip de semnal, cum combini mai multe
dovezi, ce faci cu `implies`). Nu le trata ca fiind "corecte" - citeste-le
critic, testeaza rezultatele si schimba ce nu ti se pare potrivit. Asta e
exact genul de decizie pe care Veridion vrea sa o vada argumentata de tine.
"""
from __future__ import annotations

import logging
import re

from src.fingerprints import CompiledRule, Technology
from src.models import Detection, Evidence, RawSite

logger = logging.getLogger(__name__)

# --- extragere semnale suplimentare din HTML brut -----------------------

_META_RE = re.compile(
    r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
# unele pagini scriu content inainte de name - varianta inversa
_META_RE_REV = re.compile(
    r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+name=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


def _extract_meta_tags(html: str) -> list[tuple[str, str]]:
    pairs = [(name, content) for name, content in _META_RE.findall(html)]
    pairs += [(name, content) for content, name in _META_RE_REV.findall(html)]
    return pairs


def _extract_script_srcs(html: str) -> list[str]:
    return _SCRIPT_SRC_RE.findall(html)


def _truncate(value: str, length: int = 150) -> str:
    value = value.replace("\n", " ").replace("\r", " ").strip()
    return value if len(value) <= length else value[: length - 3] + "..."


# --- ponderi de incredere per tip de semnal -------------------------------
#
# DECIZIE: un match pe `header`/`cookie`/`dns` e greu de falsificat (nu poti
# controla usor headerul de raspuns al altcuiva) - le dau incredere de baza
# mare. `script_src`/`meta` sunt aproape la fel de sigure (calea unui script
# sau un tag <meta generator> e specific). `html` e cel mai generic - un
# regex pe tot corpul paginii poate da fals-pozitive mai usor - incredere de
# baza mai mica. Poti argumenta diferit; important e sa argumentezi.
SIGNAL_BASE_CONFIDENCE: dict[str, float] = {
    "header": 0.90,
    "cookie": 0.85,
    "meta": 0.85,
    "script_src": 0.75,
    "html": 0.55,
    "dns_cname": 0.90,
    "dns_mx": 0.90,
    "dns_txt": 0.80,
    "dns_ns": 0.75,
}

# DECIZIE: `implies` (ex: WordPress implica PHP+MySQL) - le raportez, dar cu
# incredere fixa, mica, si marcate clar ca "implied" in evidence, ca sa se
# poata distinge usor de o detectie directa in output. Daca decizi ca nu au
# ce cauta (pentru ca "umfla" artificial numarul de tehnologii gasite fata
# de cele 477), seteaza asta pe False.
INCLUDE_IMPLIED_TECHNOLOGIES = True
IMPLIED_CONFIDENCE = 0.40


def _rule_confidence(rule: CompiledRule, signal_type: str) -> float:
    """
    Foloseste scorul de incredere sugerat de baza de fingerprint-uri
    (directiva `confidence:NN`, 0-100), daca exista, altfel cade pe
    ponderea de baza a tipului de semnal.
    """
    base = SIGNAL_BASE_CONFIDENCE[signal_type]
    raw = rule.directives.get("confidence")
    if raw is None:
        return base
    try:
        return (int(raw) / 100.0) * base
    except ValueError:
        return base


def _combine_confidence(evidences_confidence: list[float]) -> float:
    """
    Combina mai multe dovezi independente pentru aceeasi tehnologie.

    DECIZIE: folosesc "noisy-OR" (1 - produsul complementelor) in loc de un
    simplu maxim, ca sa recompensez tehnologiile confirmate de MULTIPLE
    semnale independente (ex: si header, si cookie, si html) fata de una
    confirmata de un singur regex slab pe html. Capat la 0.99 - nicio
    detectie automata nu ar trebui sa se declare 100% sigura.
    """
    prob_none_correct = 1.0
    for c in evidences_confidence:
        prob_none_correct *= (1.0 - c)
    return round(min(0.99, 1.0 - prob_none_correct), 3)


def _match_dict_rules(
    rules: list[CompiledRule], values: dict[str, str], signal_type: str
) -> list[Evidence]:
    evidence = []
    lowered = {k.lower(): v for k, v in values.items()}
    for rule in rules:
        value = lowered.get((rule.key or "").lower())
        if value is None:
            continue
        match = rule.pattern.search(value)
        if match:
            evidence.append(
                Evidence(signal_type=signal_type, pattern=rule.pattern.pattern, matched_value=_truncate(f"{rule.key}: {value}"))
            )
    return evidence


def _match_list_rules(rules: list[CompiledRule], haystack: str, signal_type: str) -> list[Evidence]:
    evidence = []
    for rule in rules:
        match = rule.pattern.search(haystack)
        if match:
            evidence.append(
                Evidence(signal_type=signal_type, pattern=rule.pattern.pattern, matched_value=_truncate(match.group(0)))
            )
    return evidence


def _match_meta_rules(rules: list[CompiledRule], meta_tags: list[tuple[str, str]]) -> list[Evidence]:
    evidence = []
    for name, content in meta_tags:
        for rule in rules:
            if (rule.key or "").lower() != name.lower():
                continue
            if rule.pattern.search(content):
                evidence.append(
                    Evidence(signal_type="meta", pattern=rule.pattern.pattern, matched_value=_truncate(f"{name}: {content}"))
                )
    return evidence


def _match_script_src_rules(rules: list[CompiledRule], srcs: list[str]) -> list[Evidence]:
    evidence = []
    for src in srcs:
        for rule in rules:
            if rule.pattern.search(src):
                evidence.append(
                    Evidence(signal_type="script_src", pattern=rule.pattern.pattern, matched_value=_truncate(src))
                )
    return evidence


def _match_dns_rules(rules: list[CompiledRule], records: list[str], signal_type: str) -> list[Evidence]:
    evidence = []
    for record in records:
        for rule in rules:
            if rule.pattern.search(record):
                evidence.append(
                    Evidence(signal_type=signal_type, pattern=rule.pattern.pattern, matched_value=_truncate(record))
                )
    return evidence


def _detect_one(site: RawSite, tech: Technology, meta_tags: list[tuple[str, str]], script_srcs: list[str]) -> list[Evidence]:
    evidence: list[Evidence] = []

    evidence += _match_dict_rules(tech.headers, site.headers, "header")
    evidence += _match_dict_rules(tech.cookies, site.cookies, "cookie")
    evidence += _match_meta_rules(tech.meta, meta_tags)
    evidence += _match_list_rules(tech.html, site.html, "html")
    evidence += _match_script_src_rules(tech.script_src, script_srcs)

    if tech.dns:
        evidence += _match_dns_rules(tech.dns.get("cname", []), site.dns.cname, "dns_cname")
        evidence += _match_dns_rules(tech.dns.get("mx", []), site.dns.mx, "dns_mx")
        evidence += _match_dns_rules(tech.dns.get("txt", []), site.dns.txt, "dns_txt")
        evidence += _match_dns_rules(tech.dns.get("ns", []), site.dns.ns, "dns_ns")

    return evidence


def detect_technologies(site: RawSite, technologies: dict[str, Technology]) -> list[Detection]:
    if site.error:
        return []

    meta_tags = _extract_meta_tags(site.html)
    script_srcs = _extract_script_srcs(site.html)

    detections: dict[str, Detection] = {}

    for name, tech in technologies.items():
        evidence = _detect_one(site, tech, meta_tags, script_srcs)
        if not evidence:
            continue

        confidences = [_rule_confidence(_find_rule_for_evidence(tech, e), e.signal_type) for e in evidence]
        detections[name] = Detection(
            technology=name,
            categories=tech.categories,
            confidence=_combine_confidence(confidences),
            evidence=evidence,
        )

    if INCLUDE_IMPLIED_TECHNOLOGIES:
        _add_implied(detections, technologies)

    return sorted(detections.values(), key=lambda d: d.confidence, reverse=True)


def _find_rule_for_evidence(tech: Technology, evidence: Evidence) -> CompiledRule:
    """Regasim regula compilata care a generat un Evidence, ca sa-i putem
    citi directiva de `confidence` originala din baza de date."""
    all_rules: list[CompiledRule] = (
        tech.headers + tech.cookies + tech.meta + tech.html + tech.script_src
        + [r for lst in tech.dns.values() for r in lst]
    )
    for rule in all_rules:
        if rule.pattern.pattern == evidence.pattern:
            return rule
    # fallback (nu ar trebui sa se intample) - trateaza ca html, cel mai slab semnal
    return CompiledRule(key=None, pattern=re.compile(""), directives={})


def _add_implied(detections: dict[str, Detection], technologies: dict[str, Technology]) -> None:
    directly_detected = list(detections.keys())
    for name in directly_detected:
        tech = technologies.get(name)
        if not tech:
            continue
        for implied_name in tech.implies:
            if implied_name in detections:
                continue  # deja detectat direct (sau implicat de altceva) - nu suprascriem
            implied_tech = technologies.get(implied_name)
            if not implied_tech:
                continue
            detections[implied_name] = Detection(
                technology=implied_name,
                categories=implied_tech.categories,
                confidence=IMPLIED_CONFIDENCE,
                evidence=[
                    Evidence(signal_type="implied", pattern=f"implies:{name}", matched_value=f"dedus din {name}")
                ],
            )
