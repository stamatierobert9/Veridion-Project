"""
Configurare centrala pentru pipeline.
Ajusteaza aici concurenta, timeout-urile si caile catre date, in loc sa
umbli prin cod.
"""
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
FINGERPRINTS_DIR = DATA_DIR / "fingerprints"
OUTPUT_DIR = ROOT_DIR / "output"
RAW_SNAPSHOTS_DIR = OUTPUT_DIR / "raw"  # HTML/headers brute, salvate per domeniu (util la debugging + re-rulare matcher fara re-crawl)

DOMAINS_CSV = DATA_DIR / "domains.csv"

# --- Crawler ---
HTTP_TIMEOUT_SECONDS = 12.0
MAX_CONCURRENT_REQUESTS = 25          # politicos, dar suficient pt 200 domenii in cateva minute
MAX_REDIRECTS = 8
MAX_HTML_BYTES = 3_000_000            # nu descarcam pagini de zeci de MB degeaba

# DECIZIE: matching-ul pe selectoare CSS (regulile "dom") e un tree-walk
# soupsieve per selector, si avem ~1800 de selectoare in baza de date. Pe o
# pagina normala (cateva zeci de KB) e neglijabil; pe o pagina de e-commerce
# uriasa (ex: disneystore.com/halloween-shop are 2.4MB HTML, un grid urias
# de produse) am prins efectiv procesul blocat minute intregi pe UN singur
# selector, pe O singura pagina - am confirmat cu Ctrl+C + traceback. Peste
# acest prag sarim DOAR semnalul "dom" pentru pagina respectiva (celelalte
# semnale - headers/cookies/meta/html/scriptSrc - raman neafectate, sunt
# regex simplu si scaleaza liniar cu marimea, nu au aceasta problema).
MAX_HTML_BYTES_FOR_DOM_MATCHING = 500_000
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
    "VeridionTechScraper/0.1 (+contact: robert)"
)
RETRY_ATTEMPTS = 2

# DECIZIE: dupa ce s-a terminat crawl-ul complet pe toate domeniile, mai
# facem o singura trecere suplimentara DOAR pe domeniile care au esuat cu
# un motiv care pare tranzitoriu (5xx, timeout, conexiune refuzata) - nu si
# pe cele fara niciun record DNS, care sunt aproape sigur domenii moarte.
# Am confirmat manual (curl separat, la minute distanta) ca cel putin 2
# din cele 12 domenii esuate initial raspundeau normal putin mai tarziu -
# deci o reincercare tarzie chiar recupereaza domenii reale.
RETRY_PASS_DELAY_SECONDS = 5.0

# DECIZIE: multe tehnologii traiesc doar pe pagini interne (reCAPTCHA/forms
# pe /contact, ecommerce pe /shop sau /cart, comentarii pe /blog etc.), nu
# pe homepage. Crawlem cateva pagini suplimentare de pe acelasi domeniu
# in loc de un headless browser (cost mult mai mare, vezi README pt de ce
# am ales sa NU facem asta pe acest set de date).
# DECIZIE: am crescut de la 2 la 3 pagini + adaugat cuvinte cheie noi
# (careers/jobs -> deseori un ATS extern ca Greenhouse/Lever/Workable;
# faq/support -> chat widgets; signup/register -> alte fluxuri de auth
# decat login) dupa ce am vazut ca numarul de tehnologii unice s-a
# stabilizat in jur de ~300/477 pe cateva rulari la rand - semn ca am
# atins plafonul a ce gaseste homepage + 2 pagini "evidente". Cresterea
# asta e ieftina (tot fara headless browser) si tintit exact paginile
# unde apar categorii de tehnologii pe care nu le vedem deloc inca.
# DECIZIE: am incercat 3 (in loc de 2) - a mutat numarul de tehnologii
# unice cu exact 1 (299->300), dar a triplat timpul de matching (de la
# secunde la ~15 minute pe cele 200 de domenii, din cauza selectoarelor
# CSS rulate pe mult mai multe pagini). Nu merita tradeoff-ul pe acest
# set de date - ne-am oprit la 300/477, un platou real, nu o problema
# de tuning. Revenim la 2 pagini, dar pastram cuvintele cheie noi
# (careers/faq/signup etc.) - nu costa nimic in plus, doar schimba
# PRIORITATEA linkurilor incercate cand homepage-ul are astfel de linkuri.
EXTRA_PAGES_PER_DOMAIN = 2
INTERNAL_LINK_CANDIDATES_TO_TRY = 10   # incercam pana la atatea linkuri ca sa gasim EXTRA_PAGES_PER_DOMAIN valide
INTERNAL_LINK_KEYWORDS = [
    "contact", "about", "shop", "store", "cart", "checkout",
    "blog", "news", "pricing", "product", "services", "login", "book",
    "careers", "jobs", "faq", "support", "signup", "register", "portal",
]

# --- DNS ---
DNS_TIMEOUT_SECONDS = 4.0
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

# --- Output ---
RESULTS_JSON = OUTPUT_DIR / "results.json"
RESULTS_CSV = OUTPUT_DIR / "results_flat.csv"
