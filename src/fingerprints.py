"""
Loader pentru baza de date de fingerprint-uri (formatul open-source
Wappalyzer/webappanalyzer: https://github.com/enthec/webappanalyzer).

De ce sursa asta si nu inventam noi 477 de reguli de la zero:
o baza de fingerprint-uri de calitate inseamna mii de ore de observatii
acumulate de comunitate (headere specifice, cookie-uri, pattern-uri de
script). Reinventarea ei de la zero pentru un take-home nu ar demonstra
nimic in plus fata de a folosi o baza deschisa, documentata, si a-ti pune
efortul propriu in partea care CHIAR conteaza: motorul de matching,
scorurile de incredere, semnalele suplimentare (DNS) si modul in care
prezinti dovezile. Vezi README pentru mai multe detalii despre aceasta
decizie si despre cum ai extinde/imbunatati baza de date pe viitor
(debate topic #3).

Acest modul doar PARSEAZA formatul brut intr-o structura usor de folosit
de matcher.py. Nu contine nicio decizie de "ce inseamna un match" - aia e
in matcher.py.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from src import config

# Regex-urile din formatul Wappalyzer pot contine sufixe gen:
#   "^WordPress(?: ([\d.]+))?\;version:\1"
#   "someHeaderValue\;confidence:50"
# Astea nu sunt parte din regex-ul propriu-zis, ci directive separate de
# regex printr-un ';' (scapat ca '\;'). Le separam inainte de a compila.
_DIRECTIVE_SPLIT = re.compile(r"\\;")


def _split_directives(raw: str) -> tuple[str, dict[str, str]]:
    parts = _DIRECTIVE_SPLIT.split(raw)
    pattern = parts[0]
    directives: dict[str, str] = {}
    for part in parts[1:]:
        if ":" in part:
            key, _, val = part.partition(":")
            directives[key] = val
    return pattern, directives


def _compile(raw: str) -> tuple[re.Pattern, dict[str, str]] | None:
    pattern_str, directives = _split_directives(raw)
    if not pattern_str:
        return None
    try:
        return re.compile(pattern_str, re.IGNORECASE), directives
    except re.error:
        # cateva regex-uri din baza folosesc sintaxa PCRE care nu e 100%
        # compatibila cu modulul `re` din Python; le sarim, nu blocam tot pipeline-ul.
        return None


@dataclass
class CompiledRule:
    key: str | None          # numele header-ului / cookie-ului / meta tag-ului, sau None pt html/scriptSrc/css
    pattern: re.Pattern
    directives: dict[str, str]


@dataclass
class DomCondition:
    kind: str                 # "exists" | "text" | "attribute"
    attr: str | None          # numele atributului, doar pt kind="attribute"
    pattern: re.Pattern | None  # None inseamna "doar prezenta conteaza"


@dataclass
class DomRule:
    selector: str
    conditions: list[DomCondition]


@dataclass
class Technology:
    name: str
    categories: list[str]
    implies: list[str] = field(default_factory=list)
    headers: list[CompiledRule] = field(default_factory=list)
    cookies: list[CompiledRule] = field(default_factory=list)
    meta: list[CompiledRule] = field(default_factory=list)
    html: list[CompiledRule] = field(default_factory=list)
    script_src: list[CompiledRule] = field(default_factory=list)
    dns: dict[str, list[CompiledRule]] = field(default_factory=dict)  # "cname" | "mx" | "txt" -> reguli
    dom: list[DomRule] = field(default_factory=list)


def _compile_dict_field(raw: dict | None) -> list[CompiledRule]:
    rules = []
    if not raw:
        return rules
    for key, patterns in raw.items():
        pattern_list = patterns if isinstance(patterns, list) else [patterns]
        for p in pattern_list:
            compiled = _compile(p)
            if compiled:
                rules.append(CompiledRule(key=key, pattern=compiled[0], directives=compiled[1]))
    return rules


def _compile_list_field(raw: list | str | None) -> list[CompiledRule]:
    rules = []
    if not raw:
        return rules
    items = raw if isinstance(raw, list) else [raw]
    for p in items:
        compiled = _compile(p)
        if compiled:
            rules.append(CompiledRule(key=None, pattern=compiled[0], directives=compiled[1]))
    return rules


def _compile_dom_field(raw) -> list[DomRule]:
    """
    Formatul `dom` din baza de date are doua variante:
      - lista de selectoare CSS simple: doar prezenta elementului conteaza.
      - dict: selector -> {"exists": "", "text": "regex", "attributes": {attr: regex}}
        (conditii suplimentare pe elementul gasit de selector).

    Nu tratam `properties` (proprietati JS live ale elementului in DOM) -
    astea nu exista intr-un parse static de HTML, doar la runtime intr-un
    browser real. E o limitare cunoscuta, mentionata si in README.
    """
    rules: list[DomRule] = []
    if not raw:
        return rules

    if isinstance(raw, str):
        raw = [raw]

    if isinstance(raw, list):
        for selector in raw:
            if isinstance(selector, str) and selector.strip():
                rules.append(DomRule(selector=selector, conditions=[]))
        return rules

    if isinstance(raw, dict):
        for selector, spec in raw.items():
            conditions: list[DomCondition] = []
            has_unverifiable_properties = False

            if not isinstance(spec, dict):
                conditions.append(DomCondition(kind="exists", attr=None, pattern=None))
            else:
                if "exists" in spec:
                    conditions.append(DomCondition(kind="exists", attr=None, pattern=None))
                if "text" in spec and spec["text"]:
                    compiled = _compile(spec["text"])
                    if compiled:
                        conditions.append(DomCondition(kind="text", attr=None, pattern=compiled[0]))
                for attr, value in (spec.get("attributes") or {}).items():
                    pattern = None
                    if value:
                        compiled = _compile(value)
                        pattern = compiled[0] if compiled else None
                    conditions.append(DomCondition(kind="attribute", attr=attr, pattern=pattern))

                # `properties` = proprietati JS live pe elementul DOM (ex:
                # element._reactRootContainer) - nu exista intr-un parse
                # static de HTML, doar la runtime intr-un browser real.
                # BUG PRINS IN REVIEW: daca regula avea DOAR `properties` si
                # nimic altceva verificabil, conditions ramanea gol si
                # cadeam pe fallback-ul de "doar prezenta selectorului" -
                # ceea ce transforma o regula foarte specifica (ex: React
                # cerea properties._reactRootContainer pe selectorul
                # generic "body > div") intr-una care se potrivea pe orice
                # pagina cu un div in body, adica aproape orice site.
                # Corect e sa sarim regula cu totul cand nu o putem verifica
                # deloc static, nu sa o slabim la "exists".
                has_unverifiable_properties = bool(spec.get("properties"))

                if not conditions:
                    if has_unverifiable_properties:
                        continue  # nu putem verifica nimic din regula asta static - o sarim
                    conditions.append(DomCondition(kind="exists", attr=None, pattern=None))

            rules.append(DomRule(selector=selector, conditions=conditions))
        return rules

    return rules


def load_categories() -> dict[str, str]:
    with open(config.FINGERPRINTS_DIR / "categories.json", encoding="utf-8") as f:
        raw = json.load(f)
    return {cat_id: v["name"] for cat_id, v in raw.items()}


def load_technologies() -> dict[str, Technology]:
    categories = load_categories()
    technologies: dict[str, Technology] = {}

    tech_dir = config.FINGERPRINTS_DIR / "technologies"
    for path in sorted(tech_dir.glob("*.json")):
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)

        for name, entry in raw.items():
            cat_names = [categories.get(str(c), str(c)) for c in entry.get("cats", [])]

            # DNS: in format-ul sursa e o lista de stringuri de forma "MX someregex" etc.
            dns_raw = entry.get("dns")
            dns_rules: dict[str, list[CompiledRule]] = {}
            if isinstance(dns_raw, dict):
                for rtype, patterns in dns_raw.items():
                    dns_rules[rtype.lower()] = _compile_list_field(patterns)

            technologies[name] = Technology(
                name=name,
                categories=cat_names,
                implies=entry.get("implies", []) if isinstance(entry.get("implies"), list) else (
                    [entry["implies"]] if entry.get("implies") else []
                ),
                headers=_compile_dict_field(entry.get("headers")),
                cookies=_compile_dict_field(entry.get("cookies")),
                meta=_compile_dict_field(entry.get("meta")),
                html=_compile_list_field(entry.get("html")),
                script_src=_compile_list_field(entry.get("scriptSrc")),
                dns=dns_rules,
                dom=_compile_dom_field(entry.get("dom")),
            )

    return technologies
