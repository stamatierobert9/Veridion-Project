# Veridion — Website Technologies Scraper (Deeptech Engineer Intern challenge)

A pipeline that crawls a list of domains and identifies which web technologies
each one uses, with concrete evidence attached to every detection.

## How to run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python scripts/run.py                 # crawl (HTTP + DNS) + detection, over the 200 domains in data/domains.csv
python scripts/run.py --from-cache    # re-run only the matcher against already-crawled data (no new network requests)

python -m pytest tests/ -q            # tests
```

Results land in `output/results.json` (structured, with evidence per
detection) and `output/results_flat.csv` (one row per domain-technology
pair, convenient for counting unique technologies in a spreadsheet against
the 477 mentioned in the task). Raw snapshots (HTML, headers, DNS per
domain) are cached in `output/raw/`.

**Note:** run the pipeline from a local terminal, not from a sandboxed
agent session — a restricted network allowlist there blocks crawling
arbitrary domains. The code runs correctly from a normal terminal.

## Architecture

The project is split into independent stages — crawling, DNS resolution,
fingerprint compilation, detection, and output — so that each one can be
changed, tested, or scaled without touching the others. `--from-cache`
exists specifically to decouple crawling from detection during
development: the detection logic gets iterated on dozens of times without
re-hitting the network each time, which is also the property that matters
most once this needs to run at scale (see "Scaling to millions of
domains").

```
data/domains.csv              the 200 domains from the parquet file provided
data/fingerprints/            technology database (webappanalyzer)
src/
  crawler.py                  async fetch (https -> www -> http), retries, concurrency, internal pages
  dns_lookup.py                async CNAME/MX/TXT/NS/A/AAAA lookups
  fingerprints.py               parses the fingerprint database into compiled rules
  matcher.py                    the detection engine
  models.py                     RawSite / Evidence / Detection
  pipeline.py                   ties everything together, raw-snapshot caching
  output.py                     writes JSON + CSV, prints the summary
scripts/run.py                 CLI entry point
tests/                          matcher tests
output/                          generated, gitignored
```

### `src/models.py` — shared data models

Three models are shared across every stage, so crawler, matcher, and
output all agree on the same representation:

- `RawSite` — everything collected for one page: the domain, the final
  URL after redirects, status code, response headers, HTML (capped at 3
  MB so one oversized page can't blow up memory), cookies, DNS records,
  any extra internal pages crawled for the same domain, and an `error`
  field when the fetch failed.
- `Evidence` — one concrete match: which signal type it came from
  (header, cookie, meta, html, script_src, dns, dom), the pattern that
  matched, and a truncated snippet of the actual matched value. This is
  the "proof" the task asks for.
- `Detection` — a technology name, its categories, a confidence score,
  and the list of `Evidence` that produced it.

### `src/dns_lookup.py` — DNS as an independent signal

Async DNS resolution via `dnspython`, collecting A, AAAA, CNAME, MX, TXT,
and NS records per domain, with a 4-second timeout so one broken
nameserver can't stall the whole batch.

DNS matters because it can catch technologies that leave no trace in the
HTML at all. A CNAME pointing at `shops.myshopify.com` is strong evidence
of Shopify even if the homepage HTML shows nothing Shopify-specific —
useful when a site is thin on content or a technology only reveals itself
at the infrastructure level.

### `src/fingerprints.py` — compiling the technology database

Loads the [webappanalyzer](https://github.com/enthec/webappanalyzer)
database (the community-maintained continuation of Wappalyzer, MIT
licensed) — 7,596 technologies — and compiles it once into
`Technology`/`CompiledRule`/`DomRule` objects: precompiled regexes for
headers, cookies, meta tags, HTML body, script src, and DNS, plus
CSS-selector DOM rules with optional text/attribute conditions. Doing
this once at startup, rather than re-parsing raw rule strings per domain,
moves the fixed cost out of the per-domain hot path.

I used this database rather than writing my own rules by hand: its
coverage of known CMSs, CDNs, and analytics tools is comparable to what
Veridion itself likely relies on, and reimplementing hundreds of known
signatures wouldn't have demonstrated anything about how I think. The
effort here went into the matching engine, the additional DNS signal, and
how confidence and evidence are computed and presented — that's the part
that's actually mine.

### `src/crawler.py` — fetching

Uses `httpx.AsyncClient` for concurrent async requests (up to 25 at a
time). For each domain it tries `https://domain`, then
`https://www.domain`, then `http://domain`, stopping at the first
response under 500. TLS verification is off, since a number of small
sites carry expired or self-signed certificates that would otherwise
cause them to be skipped for no good reason. Each domain also has a hard
48-second wall-clock timeout regardless of how many candidates or retries
it goes through internally — without it, a small number of slow or
misbehaving hosts could tie up workers indefinitely.

**Internal pages.** The homepage alone misses a lot: reCAPTCHA usually
only loads on a contact form, an ecommerce platform only on `/shop`,
applicant-tracking software only on `/careers`. The crawler extracts
same-domain links from the homepage, ranks them by keyword relevance
(contact, shop, blog, careers, faq, signup, etc.), and fetches up to two
of them. This is much cheaper than a full site crawl while still hitting
the pages where a lot of "hidden" technologies actually live.

**Redirect validation.** A followed link's *final* URL, after its own
redirects, is checked against the original registered domain before its
content is trusted. This came from a real case: `familybroker.cz` had
spam links injected on its homepage that redirected to unrelated
ad-fraud infrastructure (`letsgoto.pro`, `afftopbrand.com`). Without this
check, whatever that infrastructure runs would have been attributed to
`familybroker.cz` instead.

**Transient vs. permanent failures.** After the full batch runs once, any
domain that failed for a reason that looks transient (5xx, timeout,
refused connection) — as opposed to no DNS record at all — gets retried
once more after a short delay. I confirmed manually with `dig` and `curl`
that this distinction is real: four domains (`wglchurch.com` and others)
have no DNS record whatsoever and are genuinely dead, while two others
(`ecolab.com`, `sindacatobadanti.it`) returned 503/504 during the crawl
but responded normally to a manual request a few minutes later — ordinary
server-side flakiness, not dead domains. Worth noting honestly: the
automated retry pass itself recovered 0 of the ~9 domains it retried,
across two separate full runs. That doesn't mean the distinction is
wrong, just that an immediate retry after a few seconds is too short a
window to catch flakiness that resolves on the order of minutes — a
longer delay or a scheduled re-crawl would be the real fix (see "Known
issues" below).

### `src/matcher.py` — the detection engine

For every page of a domain (homepage plus whatever internal pages were
fetched), the matcher extracts meta tags and script sources with regex,
and builds a parsed DOM tree for CSS-selector matching. It then checks
every technology's rules against headers, cookies, meta tags, raw HTML,
script sources, DOM selectors, and (once, per domain rather than per
page) DNS records.

**Confidence scoring.** Each signal type gets a base confidence
reflecting how hard it is to fake: headers, cookies, and DNS CNAME/MX
records are weighted highest (0.85–0.90) because you can't easily forge
someone else's response headers or DNS; a bare regex match against the
raw HTML body is weighted lowest (0.55) because a technology's name can
show up in an article, a testimonial, or a menu item without the
technology actually being used. When a fingerprint rule specifies its own
`confidence:NN` directive, that scales the base weight rather than
replacing it. Multiple independent pieces of evidence for the same
technology are combined with noisy-OR (`1 - Π(1 - confidence)`) rather
than taking the maximum, so a technology confirmed by a script URL *and*
a header *and* a DNS record ends up meaningfully more confident than one
confirmed by a single weak HTML match — capped at 0.99, since no
automated detection should claim absolute certainty.

**Implied technologies.** Some technologies imply others — detecting
WordPress implies PHP is involved, even if nothing PHP-specific was
directly observed. These are added at a fixed, low confidence (0.40) and
tagged explicitly as `implied` evidence, so they're never confused with a
direct detection in the output.

**DOM matching cost.** Full CSS-selector matching is far more expensive
than the regex-based signals — the fingerprint database has roughly 1,800
DOM selectors, and running all of them against a large parsed document is
a real cost, not a theoretical one. I hit this directly: a 2.4 MB
product-listing page caused the matcher to sit for minutes on a single
selector, confirmed by watching the process's CPU time stay frozen in
`top` and then sending it a `Ctrl+C` to get a traceback pointing straight
at `soup.select()`. The fix was to skip building a DOM tree at all for
any page over 500 KB — that page loses only the `dom` signal; headers,
cookies, meta, html, and script_src all still run normally since they're
plain regex and scale linearly with page size instead of hitting this
cliff.

### `src/pipeline.py` / `src/output.py` — orchestration and output

`pipeline.py` loads the domain list, runs (or reuses cached) crawling and
DNS lookups, runs the matcher over every domain with progress logging
every 25 domains, and hands the results to `output.py`, which writes the
structured JSON, the flat CSV, and prints the final summary counts.

## Result against the target

- Unique technologies found: 300 / 477 (~63%)
- Total detections (domain, technology pairs): 2,056
- Domains with zero detections: 14 / 200
- Domains that failed to crawl: 13 / 200 (4 with no DNS record at all —
  dead domains; the remaining 9 were transient 5xx/timeout failures, see
  "Known issues" below)

Produced with the full webappanalyzer database (7,596 technologies) via
`python scripts/run.py` against the 200 domains in `data/domains.csv`.

### Interpretarea mea a rezultatului

Diferența de ~177 de tehnologii între cele 300 găsite de scriptul static și
targetul de 477 provine, cel mai probabil, din absența unui motor de
execuție JavaScript (headless browser) și din metodele diferite de
agregare și deducție a datelor. Fără a evalua pagina post-încărcare,
crawler-ul actual este orb la orice resursă care nu există în documentul
HTML inițial.

**Categorii de tehnologii probabil ratate**

| Categorie | Motivul lipsurilor în crawler-ul static | Exemple frecvente |
|---|---|---|
| Trackere & widget-uri | Sunt încărcate asincron prin JS târziu în ciclul de viață al paginii, adesea injectate abia după interacțiunea utilizatorului sau prin tag managere. | Intercom, Hotjar, Meta Pixel, OneTrust (Consent) |
| Biblioteci UI (ecosistem SPA) | DOM-ul static returnează un container gol (ex: `<div id="root"></div>`); componentele sunt generate exclusiv client-side de framework-uri. | Material-UI, styled-components, Redux, Zustand |
| Sisteme de plată & API-uri | Sunt inițializate dinamic pe client prin scripturi third-party asincrone, lăsând puține urme în structura de bază. | Stripe Elements, Braintree, PayPal Checkout |
| Plugin-uri de e-commerce / CMS | Extensiile injectează funcționalități prin bundle-uri JS minificate sau iframe-uri care pot fi identificate sigur doar în DOM-ul final, randat. | Plugin-uri specifice WooCommerce, module Shopify |

**Impactul metodologiei de numărare**

Modul în care Veridion definește o "tehnologie unică" poate crește rapid
numărul față de o abordare strictă de deduplicare. Dacă aș avea ocazia să
discut rezultatele, merită ridicate următoarele semne de întrebare:

- Granularitatea versiunilor: sunt Google Analytics Universal și GA4
  numărate ca două tehnologii distincte? Tratarea versiunilor majore ca
  intrări separate umflă semnificativ cifrele.
- Adâncimea arborelui de deducții (`implies`): în timp ce scriptul meu
  deduce logic PHP din prezența WordPress, un motor agresiv ar putea
  folosi lanțuri mult mai lungi (ex: detectează un modul specific ->
  deduce Apache -> deduce un mediu de rulare Linux).
- Sub-componente ale framework-urilor: dacă este detectat Next.js,
  motorul lor raportează automat și React, Node.js și Webpack ca
  tehnologii separate găsite pe același domeniu?
- Platforme gazdă și WAF-uri: domeniile mici construite pe site-builder-uri
  (Weebly, Wix) sau blocate în spatele paginilor de Cloudflare challenge
  pot raporta masiv stiva de infrastructură a gazdei (ex: Nginx, Express,
  React-ul folosit de Weebly) în loc de tehnologiile vizate de site-ul
  propriu-zis.

Această analiză arată clar că un crawler static este excelent pentru
detectarea eficientă a infrastructurii backend, serverelor web și
CMS-urilor de bază, dar un proces de crawling dinamic este esențial pentru
ecosistemul modern de marketing și frontend.

## Known issues and how I'd address them

**Client-side-rendered sites.** A React/Vue/Next app without
server-side rendering returns close to an empty shell (`<div
id="root"></div>` plus a pile of script tags) — the actual markup only
exists after the browser runs the JavaScript, so the `html`, `meta`, and
`dom` signals find almost nothing on those sites. The real fix is a
headless browser (Playwright): load the page, let it render, then match
against the resulting DOM. I decided not to add this for the 200-domain
run — Playwright is something like 10–50x more expensive per page than a
plain GET, and blanket-applying it to all 200 domains didn't seem
justified for the marginal gain on this dataset. At scale the right
version of this isn't "on" or "off" for everyone — it's a second pass
applied only to domains whose plain-HTTP crawl came back with
suspiciously little usable content, treating headless rendering as an
escalation path rather than the default (see "Scaling" below).

**WAF / challenge pages.** A Cloudflare "checking your browser" page
returns a normal HTTP 200 with real HTML, so it doesn't look like a
failure — it just means every signal the matcher finds describes
Cloudflare's challenge page, not the actual site behind it. I didn't
specifically detect this pattern in the current run. The fix would be to
fingerprint known challenge-page markers and flag those domains
separately (something like `protected_by_waf: true` plus "underlying
stack: unknown"), instead of letting Cloudflare stand in for the whole
technology stack.

**Regex false positives on generic HTML.** A technology's name or a
common string can appear in a blog post, a testimonial, or a nav menu
without the site actually running that technology. This is exactly why
`html`-signal matches are weighted lowest (0.55) and only become a
high-confidence detection once corroborated by another signal via the
noisy-OR combination — but I didn't do a targeted audit for specific
known false-positive patterns in this run.

**Transient crawl failures.** Covered above: an immediate retry after a
few seconds recovered 0 of 9 transient failures across two runs. A
production version of this would use a proper backoff schedule instead
of one immediate retry — try again after a few minutes, then hours, then
on the next scheduled crawl — before concluding a domain is genuinely
unreachable.

**DOM-matching performance on large pages.** Fixed for this run (see
`matcher.py` above) by capping DOM-selector matching to pages under 500
KB. Worth being explicit that this is a real detection tradeoff, not a
free lunch: any technology that's only detectable via a DOM selector, on
a page over 500 KB, gets missed. It only cost the pipeline's ability to
finish in a reasonable time to accept that tradeoff, and it's a small
slice of pages (large product-grid pages are the main case I saw), but
it's worth stating rather than hiding.

## Scaling to millions of domains in 1–2 months

The current split — crawl once, cache the raw snapshot, run detection
separately, re-runnable via `--from-cache` — is the same idea that
matters at scale, just distributed. Rough numbers: 5 million domains in
30 days is about 2 domains/second sustained, which isn't a bandwidth
problem — it's a problem of DNS resolution, slow/unresponsive hosts,
connection management, and CPU-bound matching, all of which need to run
on more than one machine.

Concretely: a job queue (SQS/Kafka) hands out domains to a pool of
stateless crawler workers, each of which does the same crawl this project
does today (DNS + HTTP + internal pages) and writes the raw
snapshot — HTML, headers, status, DNS, redirect chain, errors, a
timestamp — to object storage (S3), partitioned by crawl date. A pool of
egress IPs/proxies avoids one worker getting rate-limited by a single
target's WAF and taking the rest of its batch down with it.

Detection then runs as a separate, horizontally scaled batch job reading
those raw snapshots and writing partitioned Parquet output (matching the
format the input arrived in). Decoupling this from crawling has one
concrete payoff worth spelling out: if a new fingerprint gets added to
the technology database, detection can be re-run against the millions of
already-stored snapshots without re-crawling a single website. That's the
same property `--from-cache` gives this project today, just at a
different scale.

Not every domain needs the same crawl frequency — a domain whose detected
stack hasn't changed across several crawls doesn't need to be re-checked
daily, while one that changes often, or is high-traffic, deserves shorter
intervals. Headless rendering, given its cost, should stay a targeted
escalation — applied to the subset of domains a normal HTTP crawl already
flagged as low-signal/likely-SPA — rather than something every domain
goes through. Orchestration (Airflow/Step Functions), monitoring, and a
dead-letter queue for domains that fail repeatedly round this out.

## Discovering new technologies going forward

The system shouldn't be limited to whatever webappanalyzer already knows
about. A concrete way to find gaps: mine signals that show up repeatedly
across many domains but currently match nothing in the fingerprint
database — a custom response header, an unrecognized `<meta
name="generator">` value, a recurring script path or bundle name. If the
same unrecognized pattern shows up across hundreds of unrelated domains,
that's a strong, measurable signal that a real technology is missing from
the database, rather than something that has to be found by manual
guesswork.

Beyond that: keep pulling upstream updates from webappanalyzer/Wappalyzer
itself, since its community actively adds and fixes fingerprints; take
feedback from people who look at these sites manually (a sales or
research team will spot something the automated pass missed long before
a pattern-mining job would surface it); and use an LLM to help triage the
recurring-unknown-pattern list above — turning a bundle name or a script
comment into a hypothesis like "this looks like technology X" — but treat
that strictly as a hypothesis a person verifies and turns into an actual
fingerprint rule, not something trusted to create detections on its own.
