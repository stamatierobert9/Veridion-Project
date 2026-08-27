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
import time

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from src import config
from src.models import RawSite

logger = logging.getLogger(__name__)


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

        return RawSite(
            domain=domain,
            final_url=str(resp.url),
            status_code=resp.status_code,
            headers={k.lower(): v for k, v in resp.headers.items()},
            html=html,
            cookies=dict(resp.cookies),
            redirect_chain=redirect_chain,
            fetch_ms=elapsed_ms,
        )

    return RawSite(domain=domain, error=last_error or "unknown error", fetch_ms=int((time.monotonic() - start) * 1000))


# Plasa de siguranta: indiferent cate retry-uri/candidati incearca
# fetch_domain() intern, un singur domeniu nu are voie sa blocheze la
# infinit tot batch-ul. httpx.Timeout limiteaza fiecare request individual,
# dar am vazut in practica (vezi README, debate topic #1) ca unele gazde
# raspund suficient de "lent si ciudat" incat suma retry-urilor + candidatilor
# (https -> www -> http) poate depasi mult timeout-ul per-request. De-aia
# punem si un wait_for global per domeniu.
HARD_TIMEOUT_PER_DOMAIN_SECONDS = config.HTTP_TIMEOUT_SECONDS * 4


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
        verify=False,  # multe domenii mici au certificate expirate/self-signed; nu vrem sa le pierdem din cauza asta
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

        done = 0
        results: list[RawSite] = []
        for coro in asyncio.as_completed([bound_fetch(d) for d in domains]):
            site = await coro
            results.append(site)
            done += 1
            if done % 25 == 0 or done == len(domains):
                logger.info("HTTP: %d/%d domenii procesate", done, len(domains))

        by_domain = {s.domain: s for s in results}
        return [by_domain[d] for d in domains]
