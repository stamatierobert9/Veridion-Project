"""
Loader for the fingerprint database (the open-source Wappalyzer /
webappanalyzer format: https://github.com/enthec/webappanalyzer).

Why this source instead of inventing 477 rules from scratch: a
good-quality fingerprint database means thousands of hours of observations
accumulated by the community (specific headers, cookies, script
patterns). Reinventing it from scratch for a take-home wouldn't show
anything more than using an open, documented database, and putting the
effort into the part that ACTUALLY matters: the matching engine, the
confidence scores, the additional signals (DNS) and how the evidence is
presented. See README for more on this decision and on how I'd extend /
improve the database going forward.

This module only PARSES the raw format into a structure that's easy for
matcher.py to use. It contains no decision about "what counts as a match"
- that lives in matcher.py.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from src import config

# Regexes in the Wappalyzer format can contain suffixes like:
#   "^WordPress(?: ([\d.]+))?\;version:\1"
#   "someHeaderValue\;confidence:50"
# These aren't part of the regex itself, they're separate directives
# delimited from the regex by a ';' (escaped as '\;'). We split them off
# before compiling.
_DIRECTIVE_SPLIT = re.compile(r"\;")


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
        # a few regexes in the database use PCRE syntax that isn't 100%
        # compatible with Python's `re` module; we skip them rather than
        # breaking the whole pipeline.
        return None


@dataclass
class CompiledRule:
    key: str | None          # header / cookie / meta tag name, or None for html/scriptSrc/css
    pattern: re.Pattern
    directives: dict[str, str]


@dataclass
class DomCondition:
    kind: str                 # "exists" | "text" | "attribute"
    attr: str | None          # attribute name, only for kind="attribute"
    pattern: re.Pattern | None  # None means "only presence matters"


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
    dns: dict[str, list[CompiledRule]] = field(default_factory=dict)  # "cname" | "mx" | "txt" -> rules
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
    The `dom` format in the database has two variants:
      - a list of plain CSS selectors: only the element's presence matters.
      - a dict: selector -> {"exists": "", "text": "regex", "attributes": {attr: regex}}
        (extra conditions on the element found by the selector).

    We don't handle `properties` (live JS properties of the element in the
    DOM) - those don't exist in a static HTML parse, only at runtime in a
    real browser. This is a known limitation, also mentioned in the README.
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

                # `properties` = live JS properties on the DOM element (e.g.
                # element._reactRootContainer) - they don't exist in a static
                # HTML parse, only at runtime in a real browser.
                # BUG CAUGHT IN REVIEW: if the rule had ONLY `properties` and
                # nothing else verifiable, conditions stayed empty and we
                # fell back to "selector presence only" - which turned a very
                # specific rule (e.g. React required
                # properties._reactRootContainer on the generic selector
                # "body > div") into one that matched any page with a div in
                # the body, i.e. almost every site.
                # The right thing is to skip the rule entirely when we can't
                # verify any of it statically, not to weaken it to "exists".
                has_unverifiable_properties = bool(spec.get("properties"))

                if not conditions:
                    if has_unverifiable_properties:
                        continue  # nothing in this rule can be verified statically - skip it
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

            # DNS: in the source format it's a dict of record type -> list of regexes
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
