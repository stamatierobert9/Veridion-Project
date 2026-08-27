# Veridion — Website Technologies Scraper (Deeptech Engineer Intern challenge)

> Status: schela proiectului e gata si testata (crawler, DNS, loader de
> fingerprint-uri, pipeline, output). Motorul de detectie (`src/matcher.py`)
> e de implementat — acolo e partea evaluata, vezi comentariile din fisier.

## Cum ruleaza

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python scripts/run.py                 # crawl (HTTP+DNS) + detectie, pe cele 200 de domenii din data/domains.csv
python scripts/run.py --from-cache    # doar re-ruleaza matcher-ul, fara re-crawl (util cand iterezi pe matcher.py)

python -m pytest tests/ -q            # teste
```

Rezultate in `output/results.json` (structurat, cu dovezi per detectie) si
`output/results_flat.csv` (un rand per pereche domeniu-tehnologie, usor de
deschis in Sheets ca sa numeri cate tehnologii unice ai gasit fata de cele
477 mentionate in task). Snapshot-urile brute (HTML + headere + DNS per
domeniu) se salveaza in `output/raw/`.

**Notă:** rulează pipeline-ul din terminalul tău local (nu din sesiunea
Claude) — sandboxul din Cowork are un allowlist de rețea restrictiv care
blochează accesul la domenii arbitrare, așa că `device_bash` nu poate
crawla efectiv `jackwills.com` etc. Codul e testat și rulează corect din
Terminal.app pe Mac-ul tău.

## Arhitectura

```
data/domains.csv              # cele 200 de domenii din parquet-ul primit
data/fingerprints/            # baza de tehnologii (webappanalyzer, ~2500 de tehnologii)
src/
  crawler.py                  # fetch async (https -> www -> http), httpx, retry, concurenta
  dns_lookup.py                # CNAME/MX/TXT/NS async, dnspython
  fingerprints.py               # parseaza baza de date in structuri usor de folosit
  matcher.py                    # <<< AICI SCRII TU LOGICA DE DETECTIE >>>
  models.py                     # RawSite / Evidence / Detection
  pipeline.py                   # leaga totul, salveaza/refoloseste cache brut
  output.py                     # scrie JSON + CSV, printeaza sumar (nr tehnologii unice gasite)
scripts/run.py                 # CLI
tests/                          # teste pentru matcher
output/                          # generat, .gitignored
```

De ce aceasta impartire: crawling-ul (partea de retea) si detectia (partea
de logica) sunt complet separate. `--from-cache` iti permite sa re-rulezi
matcher-ul de sute de ori, fara sa mai lovesti reteaua de fiecare data — cand
lucrezi pe imbunatatirea scorurilor de incredere, asta conteaza mult.

## De ce am ales baza de fingerprint-uri webappanalyzer

Am pornit de la baza de date open-source
[webappanalyzer](https://github.com/enthec/webappanalyzer) (continuarea
comunitatii a proiectului original Wappalyzer, MIT licensed). Contine
semnaturi (regex-uri) pentru headere HTTP, cookie-uri, meta tag-uri, HTML,
`<script src>`, si DNS, pentru mii de tehnologii — acoperirea e comparabila
cu ce a folosit probabil si Veridion. Nu are sens sa reinventez manual
sute de regex-uri pentru CMS-uri/CDN-uri/analytics cunoscute; efortul meu
propriu s-a dus in motorul de matching, in semnalele suplimentare (DNS) si
in cum evaluez si prezint increderea/dovezile — asta e partea care chiar
arata cum gandesc, nu regex-urile in sine.

## Plan de implementare (pana la 21 septembrie)

- [x] Setup repo, dependinte, structura
- [x] Crawler async (HTTP) — https -> www -> http fallback, redirect chain, cookies, headere
- [x] Colectare DNS async (CNAME/MX/TXT/NS)
- [x] Loader baza de fingerprint-uri (webappanalyzer, parsare + compilare regex)
- [x] Pipeline + output (JSON structurat + CSV flat) + cache pentru raw snapshots
- [ ] **`src/matcher.py`** — motorul de detectie propriu-zis (headers, cookies, meta, html, scriptSrc, dns)
- [ ] Scor de incredere per detectie + strategie de dedup (vezi TODO-urile din matcher.py)
- [ ] Decizie + implementare pentru `implies` (ex: WordPress implica PHP+MySQL — le raportezi?)
- [ ] Rulare completa pe cele 200 de domenii, comparare cu target-ul de 477 tehnologii
- [ ] (optional, daca ramane timp) pas cu headless browser (Playwright) pentru site-urile SPA
  unde HTML-ul static nu contine suficiente semnale (React/Vue randate client-side)
- [ ] Scris explicatia/prezentarea solutiei + raspunsurile la debate topics
- [ ] Curatenie finala, README, submit link Github

## Debate topics

*(De completat de tine, in cuvintele tale — astea sunt doar puncte de plecare / intrebari la care sa raspunzi, nu raspunsuri.)*

### 1. Ce probleme are implementarea curenta si cum le-ai rezolva?

Cateva directii de investigat (adauga-le pe ale tale, pe masura ce rulezi
pe cele 200 de domenii si vezi ce lipseste):

- Site-uri randate client-side (React/Vue/Next fara SSR) — HTML-ul static
  nu contine markup-ul real, deci semnalele din `html`/`meta` lipsesc.
  Cum ai decide cand merita costul unui pas cu headless browser?
- WAF-uri / Cloudflare challenge pages — raspunsul primit nu e site-ul
  real, ci o pagina de verificare. Cum distingi asta de "site-ul chiar nu
  exista"?
- Regex-uri generice care dau fals-pozitiv (ex: un string comun in `html`
  care se potriveste intamplator).
- Domenii care redirectioneaza complet in alta parte (ex: catre un alt
  domeniu, un parking page, sau catre HTTPS cu certificat invalid).
- Site-uri foarte mici (ex: cele de pe `weebly.com`, `booked.net`,
  `business.site` din lista) — platforma "gazda" ar trebui raportata ca
  tehnologie a domeniului?

### 2. Cum ai scala solutia la milioane de domenii, in 1-2 luni?

Puncte de plecare (dezvolta-le cu cifre concrete — cate domenii/secunda
iti trebuie ca sa acoperi X milioane in Y zile, si ce inseamna asta pentru
infrastructura):

- Separarea crawl-ului de detectie: crawlezi o data, salvezi raw
  HTML/headere/DNS in object storage (S3, partitionat), rulezi detectia ca
  job batch separat — asta iti permite sa imbunatatesti fingerprint-urile
  fara sa re-crawlezi.
- Coada de job-uri (SQS/Kafka) + workeri orizontal scalabili, fiecare
  procesand un batch de domenii; pool de IP-uri/proxy-uri ca sa nu fii
  blocat de rate-limiting per-domeniu.
- Politica de reincercare si de "freshness" — nu toate domeniile trebuie
  re-crawlite la fel de des.
- Format de stocare columnar (Parquet, ca cel primit) pentru output,
  partitionat pe zi/batch.
- Orchestrare (Airflow/Step Functions), monitorizare, dead-letter queue
  pentru domenii care esueaza constant.
- Headless browser (Playwright) doar pentru un subset (site-urile unde
  crawl-ul static nu gaseste suficiente semnale) — ruleaza mult mai
  incet/scump decat un simplu GET.

### 3. Cum ai descoperi tehnologii noi in viitor?

Puncte de plecare:

- Mineri semnale nerecunoscute repetate: headere custom, `<meta
  name="generator">` cu valori necunoscute, cai de script (`/wp-content/`
  style) care apar des dar nu sunt in baza de date.
- Monitorizare a actualizarilor bazei webappanalyzer/Wappalyzer (comunitate
  activa care adauga tehnologii noi constant).
- Feedback loop de la echipa de vanzari — ei vad manual tehnologii pe care
  tool-ul le rateaza.
- Folosirea unui LLM pentru a clasifica/eticheta pattern-uri necunoscute
  dar frecvente (nume de bundle-uri JS, comentarii in cod sursa) ca ipoteze
  de noi tehnologii, verificate ulterior manual.

## Rezultat fata de target

*(completezi dupa ce rulezi pipeline-ul complet)*

- Tehnologii unice gasite: __ / 477
- Domenii fara nicio detectie: __ / 200
