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

# --- DNS ---
DNS_TIMEOUT_SECONDS = 4.0
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

# --- Output ---
RESULTS_JSON = OUTPUT_DIR / "results.json"
RESULTS_CSV = OUTPUT_DIR / "results_flat.csv"
