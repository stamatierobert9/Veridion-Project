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
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
    "VeridionTechScraper/0.1 (+contact: robert)"
)
RETRY_ATTEMPTS = 2

# DECIZIE: multe tehnologii traiesc doar pe pagini interne (reCAPTCHA/forms
# pe /contact, ecommerce pe /shop sau /cart, comentarii pe /blog etc.), nu
# pe homepage. Crawlem cateva pagini suplimentare de pe acelasi domeniu
# in loc de un headless browser (cost mult mai mare, vezi README pt de ce
# am ales sa NU facem asta pe acest set de date).
EXTRA_PAGES_PER_DOMAIN = 2
INTERNAL_LINK_CANDIDATES_TO_TRY = 6   # incercam pana la atatea linkuri ca sa gasim EXTRA_PAGES_PER_DOMAIN valide
INTERNAL_LINK_KEYWORDS = [
    "contact", "about", "shop", "store", "cart", "checkout",
    "blog", "news", "pricing", "product", "services", "login", "book",
]

# --- DNS ---
DNS_TIMEOUT_SECONDS = 4.0
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

# --- Output ---
RESULTS_JSON = OUTPUT_DIR / "results.json"
RESULTS_CSV = OUTPUT_DIR / "results_flat.csv"
