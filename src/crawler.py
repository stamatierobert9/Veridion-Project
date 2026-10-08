"""
Async crawler: takes a domain, tries https then http, follows redirects and
returns a RawSite with everything it managed to collect.

Why httpx and not requests: httpx has a native async client (AsyncClient),
which lets us run N concurrent requests on a single event loop instead of
opening N threads. For 200 domains the difference is small, but this is
the architecture that scales towards millions of domains (see README,
scaling section).
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from urllib.parse import urljoin, urlparse

import httpx
import tldextract
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from src import config
from src.models import RawSite

logger = logging.getLogger(__name__)

_LINK_RE = re.compile(r'<a[^>]+href=["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)


def _registered_domain(host: str) -> str:
    """www.example.co.uk -> example.co.uk (uses the public suffix list, not just the last 2 labels)."""
    ext = tldextract.extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


def _rank_internal_link(url: str) -> int:
    path = urlparse(url).path.lower()
    for i, keyword in enumerate(config.INTERNAL_LINK_KEYWORDS):
        if keyword in path:
            return i
    return len(config.INTERNAL_LINK_KEYWORDS)


def _extract_internal_links(html: str, base_url: str, registered_domain: str) -> list[str]:
    """
    Extracts links to other pages on the SAME domain (not external ones),
    prioritized by relevant keywords (contact/shop/blog etc., see
    config.INTERNAL_LINK_KEYWORDS) - these are the pages where technologies
    that aren't visible on the homepage show up most often (forms ->
    reCAPTCHA, shop -> ecommerce platform, blog -> comments/embeds).
    """
    seen: set[str] = set()
    links: list[str] = []
    for href in _LINK_RE.findall(html):
        href = href.strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if _registered_domain(parsed.netloc) != registered_domain:
            continue  # external link - we only care about this domain
        absolute = absolute.split("#")[0]
        if absolute in seen or absolute == base_url:
            continue
        seen.add(absolute)
        links.append(absolute)

    links.sort(key=_rank_internal_link)
    return links[: config.INTERNAL_LINK_CANDIDATES_TO_TRY]


class TransientFetchError(Exception):
    pass


@retry(
    reraise=True,
    stop=stop_after_attempt(config.RETRY_ATTEMPTS),
    wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
    retry=retry_if_exception_type(TransientFetchError),
)
async def _fetch_once(client: httpx.AsyncClient, url: str) -> httpx.Response:
    try:
        resp = await client.get(url, follow_redirects=True)
        return resp
    except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout) as exc:
        raise TransientFetchError(str(exc)) from exc


async def fetch_domain(client: httpx.AsyncClient, domain: str) -> RawSite:
    """
    Tries https://domain, then https://www.domain, then http://domain.
    Stops at the first valid response (status < 500).

    Known limitation: we don't currently distinguish between "the domain
    really doesn't respond" and "it's behind a WAF/Cloudflare challenge
    page". See README, "Known issues".
    """
    candidates = [f"https://{domain}", f"https://www.{domain}", f"http://{domain}"]
    last_error = None
    start = time.monotonic()

    for url in candidates:
        try:
            resp = await _fetch_once(client, url)
        except Exception as exc:  # noqa: BLE001 - we want to try the next candidate regardless
            # DECISION: many httpx exceptions (SSL, connection refused) have
            # an empty str(exc) - without the exception type you end up with
            # "unknown error" in the log, which tells you nothing useful when
            # you want to explain why some domains consistently fail.
            detail = str(exc) or repr(exc)
            last_error = f"{type(exc).__name__}: {detail}"
            continue

        if resp.status_code >= 500:
            last_error = f"HTTP {resp.status_code} on {url}"
            continue

        html = ""
        content_type = resp.headers.get("content-type", "")
        if "text" in content_type or "html" in content_type or content_type == "":
            html = resp.text[: config.MAX_HTML_BYTES]

        elapsed_ms = int((time.monotonic() - start) * 1000)
        redirect_chain = [str(r.url) for r in resp.history] + [str(resp.url)]

        site = RawSite(
            domain=domain,
            final_url=str(resp.url),
            status_code=resp.status_code,
            headers={k.lower(): v for k, v in resp.headers.items()},
            html=html,
            cookies=dict(resp.cookies),
            redirect_chain=redirect_chain,
            fetch_ms=elapsed_ms,
        )

        if config.EXTRA_PAGES_PER_DOMAIN > 0 and html:
            site.extra_pages = await _fetch_extra_pages(client, domain, str(resp.url), html)

        return site

    return RawSite(domain=domain, error=last_error or "unknown error", fetch_ms=int((time.monotonic() - start) * 1000))


async def _fetch_extra_pages(client: httpx.AsyncClient, domain: str, base_url: str, homepage_html: str) -> list[RawSite]:
    """
    Tries up to INTERNAL_LINK_CANDIDATES_TO_TRY internal links (prioritized
    by keyword) and stops once EXTRA_PAGES_PER_DOMAIN valid pages have been
    fetched. Each failure (404, timeout, etc.) is silently ignored - it's
    normal for some of the "guessed" links not to exist.
    """
    registered = _registered_domain(urlparse(base_url).netloc)
    candidates = _extract_internal_links(homepage_html, base_url, registered)

    extra_pages: list[RawSite] = []
    for link in candidates:
        if len(extra_pages) >= config.EXTRA_PAGES_PER_DOMAIN:
            break
        try:
            resp = await _fetch_once(client, link)
        except Exception:  # noqa: BLE001 - one failed internal page shouldn't stop the rest
            continue
        if resp.status_code >= 400:
            continue

        # DECISION: we also validate the FINAL domain (after redirects), not
        # just the initial link. I found domains (e.g. familybroker.cz) with
        # injected spam links that redirect to completely unrelated ad-fraud
        # infrastructure (e.g. letsgoto.pro, afftopbrand.com) - without this
        # check, we'd attribute the technologies detected on the foreign
        # domain to the original host.
        final_registered = _registered_domain(urlparse(str(resp.url)).netloc)
        if final_registered != registered:
            continue

        extra_html = ""
        content_type = resp.headers.get("content-type", "")
        if "text" in content_type or "html" in content_type or content_type == "":
            extra_html = resp.text[: config.MAX_HTML_BYTES]

        extra_pages.append(
            RawSite(
                domain=domain,
                final_url=str(resp.url),
                status_code=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                html=extra_html,
                cookies=dict(resp.cookies),
            )
        )

    return extra_pages


# Safety net: no matter how many retries/candidates fetch_domain() tries
# internally, a single domain must not be allowed to block the whole batch
# forever. httpx.Timeout caps each individual request, but in practice
# (see README, "Known issues") some hosts respond "slowly and strangely"
# enough that the sum of retries + candidates (https -> www -> http) can
# far exceed the per-request timeout. Hence a global wait_for per domain.
HARD_TIMEOUT_PER_DOMAIN_SECONDS = config.HTTP_TIMEOUT_SECONDS * 4


# DECISION: distinguish "dead" domains (no DNS at all - no point retrying)
# from transient failures (5xx, timeout, connection refused at that
# moment). I manually checked a few domains that kept failing (see README,
# "Known issues"): ecolab.com and sindacatobadanti.it returned 504/503
# during the crawl but worked fine with a manual curl a few minutes later -
# server-side flakiness, not a real problem with the domain. Domains like
# wglchurch.com, on the other hand, have NO DNS record at all (`dig +short
# A` is empty) - those are truly dead and retrying them only wastes time.
_DEAD_DOMAIN_ERROR_MARKERS = (
    "nodename nor servname",  # macOS/BSD getaddrinfo
    "name or service not known",  # Linux getaddrinfo
    "getaddrinfo failed",  # Windows
    "no address associated",
)


def _looks_permanently_dead(error: str | None) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return any(marker in lowered for marker in _DEAD_DOMAIN_ERROR_MARKERS)


async def fetch_all(domains: list[str]) -> list[RawSite]:
    limits = httpx.Limits(max_connections=config.MAX_CONCURRENT_REQUESTS, max_keepalive_connections=config.MAX_CONCURRENT_REQUESTS)
    timeout = httpx.Timeout(config.HTTP_TIMEOUT_SECONDS)
    headers = {"User-Agent": config.USER_AGENT, "Accept-Language": "en-US,en;q=0.8"}
    semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_REQUESTS)

    async with httpx.AsyncClient(
        http2=True,
        limits=limits,
        timeout=timeout,
        headers=headers,
        max_redirects=config.MAX_REDIRECTS,
        verify=False,  # many small domains have expired/self-signed certificates; we don't want to lose them because of that
    ) as client:

        async def bound_fetch(domain: str) -> RawSite:
            async with semaphore:
                try:
                    return await asyncio.wait_for(
                        fetch_domain(client, domain), timeout=HARD_TIMEOUT_PER_DOMAIN_SECONDS
                    )
                except asyncio.TimeoutError:
                    logger.warning("hard timeout (%ss) on %s - marking it as failed and moving on", HARD_TIMEOUT_PER_DOMAIN_SECONDS, domain)
                    return RawSite(domain=domain, error=f"hard timeout after {HARD_TIMEOUT_PER_DOMAIN_SECONDS}s")

        async def run_pass(target_domains: list[str]) -> list[RawSite]:
            done = 0
            pass_results: list[RawSite] = []
            for coro in asyncio.as_completed([bound_fetch(d) for d in target_domains]):
                site = await coro
                pass_results.append(site)
                done += 1
                if done % 25 == 0 or done == len(target_domains):
                    logger.info("HTTP: %d/%d domains processed", done, len(target_domains))
            return pass_results

        results = await run_pass(domains)
        by_domain = {s.domain: s for s in results}

        retryable = [
            s.domain for s in results if s.error and not _looks_permanently_dead(s.error)
        ]
        if retryable:
            logger.info(
                "%d domains failed transiently (they don't look permanently dead) - retrying once after a short pause: %s",
                len(retryable), ", ".join(retryable),
            )
            await asyncio.sleep(config.RETRY_PASS_DELAY_SECONDS)
            retry_results = await run_pass(retryable)
            recovered = 0
            for site in retry_results:
                if not site.error:
                    recovered += 1
                by_domain[site.domain] = site
            logger.info("retry: %d/%d domains recovered", recovered, len(retryable))

        return [by_domain[d] for d in domains]
