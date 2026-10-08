"""
The detection engine: takes a RawSite and the Technology database and
returns a list of Detection objects, each with concrete evidence.

The judgment calls are marked explicitly with "# DECISION:" - the
confidence score per signal type, how multiple pieces of evidence are
combined, and what happens with `implies`. See README for the reasoning
behind each one.
"""
from __future__ import annotations

import logging
import re

from bs4 import BeautifulSoup

from src import config
from src.fingerprints import CompiledRule, DomRule, Technology
from src.models import Detection, Evidence, RawSite

logger = logging.getLogger(__name__)

# --- extracting additional signals from raw HTML -------------------------

_META_RE = re.compile(
    r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
# some pages write content before name - reversed variant
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


# --- confidence weights per signal type ------------------------------------
#
# DECISION: a match on `header`/`cookie`/`dns` is hard to fake (you can't
# easily control someone else's response headers) - these get a high base
# confidence. `script_src`/`meta` are almost as reliable (a script path or a
# <meta generator> tag is specific). `html` is the most generic - a regex
# over the whole page body produces false positives more easily - so it
# gets a lower base confidence.
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
    "dom": 0.80,
}

# DECISION: `implies` (e.g. WordPress implies PHP+MySQL) - I report them,
# but with a fixed, low confidence and clearly marked as "implied" in the
# evidence, so they're easy to tell apart from a direct detection in the
# output. Set this to False to exclude them (e.g. if they're considered to
# artificially inflate the number of technologies found vs. the 477).
INCLUDE_IMPLIED_TECHNOLOGIES = True
IMPLIED_CONFIDENCE = 0.40


def _rule_confidence(rule: CompiledRule, signal_type: str) -> float:
    """
    Uses the confidence suggested by the fingerprint database (the
    `confidence:NN` directive, 0-100) to scale the signal type's base
    weight, if present; otherwise falls back to the base weight.
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
    Combines multiple independent pieces of evidence for the same technology.

    DECISION: I use "noisy-OR" (1 - product of complements) instead of a
    simple max, to reward technologies confirmed by MULTIPLE independent
    signals (e.g. header, cookie and html) over one confirmed by a single
    weak html regex. Capped at 0.99 - no automated detection should claim
    to be 100% certain.
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


def _match_dom_rules(rules: list[DomRule], soup: BeautifulSoup | None) -> list[Evidence]:
    if soup is None:
        return []
    evidence = []
    for rule in rules:
        try:
            elements = soup.select(rule.selector)
        except Exception:  # noqa: BLE001 - "exotic" CSS selectors that soupsieve doesn't support - skip them
            continue
        if not elements:
            continue

        if not rule.conditions:
            evidence.append(Evidence(signal_type="dom", pattern=rule.selector, matched_value=_truncate(str(elements[0])[:150])))
            continue

        for element in elements:
            if _element_satisfies_conditions(element, rule.conditions):
                evidence.append(Evidence(signal_type="dom", pattern=rule.selector, matched_value=_truncate(str(element)[:150])))
                break  # one element that satisfies the conditions is enough for this rule

    return evidence


def _element_satisfies_conditions(element, conditions: list) -> bool:
    for cond in conditions:
        if cond.kind == "exists":
            continue  # we already know the selector found something
        if cond.kind == "text":
            text = element.get_text() if hasattr(element, "get_text") else ""
            if not (cond.pattern and cond.pattern.search(text)):
                return False
        elif cond.kind == "attribute":
            value = element.get(cond.attr) if hasattr(element, "get") else None
            if value is None:
                return False
            if cond.pattern is not None and not cond.pattern.search(str(value)):
                return False
    return True


def _page_context(page: RawSite) -> tuple[list[tuple[str, str]], list[str], BeautifulSoup | None]:
    meta_tags = _extract_meta_tags(page.html)
    script_srcs = _extract_script_srcs(page.html)
    soup = None
    if page.html and len(page.html) <= config.MAX_HTML_BYTES_FOR_DOM_MATCHING:
        try:
            soup = BeautifulSoup(page.html, "html.parser")
        except Exception:  # noqa: BLE001 - badly malformed HTML - we only drop the dom signal for this page
            soup = None
    elif page.html:
        # DECISION: see config.MAX_HTML_BYTES_FOR_DOM_MATCHING - this page
        # is too large for ~1800 CSS selectors (I caught a concrete case
        # that blocked the process for minutes). We only lose the "dom"
        # signal for it; the other signals (headers/cookies/meta/html/
        # scriptSrc) are still computed normally.
        logger.warning(
            "page too large (%d bytes) for dom matching, skipping - %s",
            len(page.html), page.final_url or page.domain,
        )
    return meta_tags, script_srcs, soup


def _page_evidence(
    page: RawSite, tech: Technology, meta_tags: list[tuple[str, str]], script_srcs: list[str], soup: BeautifulSoup | None
) -> list[Evidence]:
    """Signals that belong to a specific PAGE (not the whole domain) -
    headers, cookies, meta, html, script_src, dom. DNS is separate: it's
    domain-level, so there's no point repeating it per page."""
    evidence: list[Evidence] = []
    evidence += _match_dict_rules(tech.headers, page.headers, "header")
    evidence += _match_dict_rules(tech.cookies, page.cookies, "cookie")
    evidence += _match_meta_rules(tech.meta, meta_tags)
    evidence += _match_list_rules(tech.html, page.html, "html")
    evidence += _match_script_src_rules(tech.script_src, script_srcs)
    evidence += _match_dom_rules(tech.dom, soup)
    return evidence


def _dns_evidence(dns, tech: Technology) -> list[Evidence]:
    evidence: list[Evidence] = []
    if tech.dns:
        evidence += _match_dns_rules(tech.dns.get("cname", []), dns.cname, "dns_cname")
        evidence += _match_dns_rules(tech.dns.get("mx", []), dns.mx, "dns_mx")
        evidence += _match_dns_rules(tech.dns.get("txt", []), dns.txt, "dns_txt")
        evidence += _match_dns_rules(tech.dns.get("ns", []), dns.ns, "dns_ns")
    return evidence


def detect_technologies(site: RawSite, technologies: dict[str, Technology]) -> list[Detection]:
    if site.error:
        return []

    # DECISION: many technologies don't show up on the homepage (reCAPTCHA
    # on /contact, ecommerce platform on /shop, comments on /blog) - see
    # config.EXTRA_PAGES_PER_DOMAIN and crawler._fetch_extra_pages. We treat
    # them all as "pages of the same domain": homepage + the internal pages
    # found during the crawl. The DOM is parsed once per page (not per
    # technology) - "html.parser" is built in (no lxml dependency); if
    # performance becomes a problem at larger scale, lxml is the obvious
    # replacement.
    pages = [site] + [p for p in site.extra_pages if not p.error and p.html]
    page_contexts = [_page_context(p) for p in pages]

    detections: dict[str, Detection] = {}

    for name, tech in technologies.items():
        evidence: list[Evidence] = list(_dns_evidence(site.dns, tech))

        for page, (meta_tags, script_srcs, soup) in zip(pages, page_contexts):
            page_evidence = _page_evidence(page, tech, meta_tags, script_srcs, soup)
            if page is not site:
                # mark clearly that the evidence comes from a page other than
                # the homepage, so the output shows where the "proof" came from
                for e in page_evidence:
                    e.matched_value = f"[{page.final_url or page.domain}] {e.matched_value}"
            evidence += page_evidence

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
    """Finds the compiled rule that produced an Evidence, so we can read
    its original `confidence` directive from the database."""
    if evidence.signal_type == "dom":
        # dom rules aren't CompiledRules (no regex) - they have no
        # confidence directive of their own, so the signal's base weight applies.
        return CompiledRule(key=None, pattern=re.compile(""), directives={})

    all_rules: list[CompiledRule] = (
        tech.headers + tech.cookies + tech.meta + tech.html + tech.script_src
        + [r for lst in tech.dns.values() for r in lst]
    )
    for rule in all_rules:
        if rule.pattern.pattern == evidence.pattern:
            return rule
    # fallback (shouldn't happen) - no directive, so the signal's base weight applies
    return CompiledRule(key=None, pattern=re.compile(""), directives={})


def _add_implied(detections: dict[str, Detection], technologies: dict[str, Technology]) -> None:
    directly_detected = list(detections.keys())
    for name in directly_detected:
        tech = technologies.get(name)
        if not tech:
            continue
        for implied_name in tech.implies:
            if implied_name in detections:
                continue  # already detected directly (or implied by something else) - don't overwrite
            implied_tech = technologies.get(implied_name)
            if not implied_tech:
                continue
            detections[implied_name] = Detection(
                technology=implied_name,
                categories=implied_tech.categories,
                confidence=IMPLIED_CONFIDENCE,
                evidence=[
                    Evidence(signal_type="implied", pattern=f"implies:{name}", matched_value=f"implied by {name}")
                ],
            )
