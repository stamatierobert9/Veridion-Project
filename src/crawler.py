"""
Crawler async: ia un domeniu, incearca https apoi http, urmareste
redirect-urile si intoarce un RawSite cu tot ce a putut culege.

De ce httpx si nu requests: httpx are un client async nativ (AsyncClient),
ceea ce ne permite sa lansam N cereri concurente cu un singur event loop,
in loc sa deschidem N thread-uri. Pentru 200 de domenii diferenta e mica,
dar arhitectura asta e cea care scaleaza spre milioane de domenii
(vezi README, sectiunea de scalare).
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
    """www.example.co.uk -> example.co.uk (foloseste lista publica de sufixe, nu doar ultimele 2 segmente)."""
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
    Extrage linkuri catre alte pagini de pe ACELASI domeniu (nu externe),
    prioritizate dupa cuvinte cheie relevante (contact/shop/blog etc,
    vezi config.INTERNAL_LINK_KEYWORDS) - astea sunt paginile unde apar cel
    mai des tehnologii care nu se vad pe homepage (formulare -> reCAPTCHA,
    shop -> platforma de ecommerce, blog -> comentarii/embed-uri).
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
            continue  # link extern - ne intereseaza doar acest domeniu
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
    Incearca https://domain, apoi https://www.domain, apoi http://domain.
    Se opreste la primul raspuns valid (status < 500).

    NOTA pt tine: aici e un loc bun de imbunatatit - momentan nu distingem
    intre "domeniul chiar nu raspunde" si "e blocat de un WAF/Cloudflare
    challenge page". Vezi README, debate topic #1.
    """
    candidates = [f"https://{domain}", f"https://www.{domain}", f"http://{domain}"]
    last_error = None
    start = time.monotonic()

    for url in candidates:
        try:
            resp = await _fetch_once(client, url)
        except Exception as exc:  # noqa: BLE001 - vrem sa incercam urmatorul candidat oricum
            # DECIZIE: multe exceptii httpx (SSL, connection refused) au
            # str(exc) gol - fara tipul exceptiei, ajungi cu "unknown error"
            # in log, ceea ce nu-ti spune nimic util cand vrei sa explici in
            # README de ce anume au esuat cateva domenii constant.
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
    Incearca pana la INTERNAL_LINK_CANDIDATES_TO_TRY linkuri interne
    (prioritizate dupa cuvinte cheie) si opreste-te dupa ce ai reusit
    EXTRA_PAGES_PER_DOMAIN pagini valide. Fiecare esec (404, timeout, etc.)
    e ignorat silentios - e normal ca nu toate linkurile "ghicite" sa existe.
    """
    registered = _registered_domain(urlparse(base_url).netloc)
    candidates = _extract_internal_links(homepage_html, base_url, registered)

    extra_pages: list[RawSite] = []
    for link in candidates:
        if len(extra_pages) >= config.EXTRA_PAGES_PER_DOMAIN:
            break
        try:
            resp = await _fetch_once(client, link)
        except Exception:  # noqa: BLE001 - o pagina interna esuata nu trebuie sa opreasca restul
            continue
        if resp.status_code >= 400:
            continue

        # DECIZIE: validam si domeniul FINAL (dupa redirect), nu doar linkul
        # initial. Am gasit domenii (ex: familybroker.cz) cu linkuri de spam
        # injectate care redirectioneaza catre infrastructura de ad-fraud
        # complet straina (ex: letsgoto.pro, afftopbrand.com) - fara acest
        # check, am fi atribuit gazdei originale tehnologiile detectate pe
        # domeniul strain catre care a redirectionat.
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


# Plasa de siguranta: indiferent cate retry-uri/candidati incearca
# fetch_domain() intern, un singur domeniu nu are voie sa blocheze la
# infinit tot batch-ul. httpx.Timeout limiteaza fiecare request individual,
# dar am vazut in practica (vezi README, debate topic #1) ca unele gazde
# raspund suficient de "lent si ciudat" incat suma retry-urilor + candidatilor
# (https -> www -> http) poate depasi mult timeout-ul per-request. De-aia
# punem si un wait_for global per domeniu.
HARD_TIMEOUT_PER_DOMAIN_SECONDS = config.HTTP_TIMEOUT_SECONDS * 4


# DECIZIE: distingem domenii "moarte" (nu exista DNS deloc pentru ele -
# nu are sens sa reincercam) de esecuri tranzitorii (5xx, timeout, conexiune
# refuzata la momentul respectiv). Am verificat manual cateva domenii care
# esuau constant (vezi README, debate topic #1): ecolab.com si
# sindacatobadanti.it au raspuns cu 504/503 in crawl dar functionau normal
# la un curl manual la cateva minute distanta - server-side flakiness, nu
# o problema reala a domeniului. In schimb domenii ca wglchurch.com nu au
# NICIUN record DNS (`dig +short A` gol) - alea sunt moarte de-a binelea si
# reincercarea lor doar pierde timp.
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
        verify=False,  # multe domenii mici au certificate expirate/self-signate; nu vrem sa le pierdem din cauza asta
    ) as client:

        async def bound_fetch(domain: str) -> RawSite:
            async with semaphore:
                try:
                    return await asyncio.wait_for(
                        fetch_domain(client, domain), timeout=HARD_TIMEOUT_PER_DOMAIN_SECONDS
                    )
                except asyncio.TimeoutError:
                    logger.warning("hard timeout (%ss) pe %s - il marchez ca esuat si continui", HARD_TIMEOUT_PER_DOMAIN_SECONDS, domain)
                    return RawSite(domain=domain, error=f"hard timeout after {HARD_TIMEOUT_PER_DOMAIN_SECONDS}s")

        async def run_pass(target_domains: list[str]) -> list[RawSite]:
            done = 0
            pass_results: list[RawSite] = []
            for coro in asyncio.as_completed([bound_fetch(d) for d in target_domains]):
                site = await coro
                pass_results.append(site)
                done += 1
                if done % 25 == 0 or done == len(target_domains):
                    logger.info("HTTP: %d/%d domenii procesate", done, len(target_domains))
            return pass_results

        results = await run_pass(domains)
        by_domain = {s.domain: s for s in results}

        retryable = [
            s.domain for s in results if s.error and not _looks_permanently_dead(s.error)
        ]
        if retryable:
            logger.info(
                "%d domenii au esuat tranzitoriu (nu par moarte definitiv) - reincerc o data dupa o pauza scurta: %s",
                len(retryable), ", ".join(retryable),
            )
            await asyncio.sleep(config.RETRY_PASS_DELAY_SECONDS)
            retry_results = await run_pass(retryable)
            recovered = 0
            for site in retry_results:
                if not site.error:
                    recovered += 1
                by_domain[site.domain] = site
            logger.info("reincercare: %d/%d domenii recuperate", recovered, len(retryable))

        return [by_domain[d] for d in domains]
