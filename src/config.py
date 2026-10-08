"""
Central configuration for the pipeline.
Tune concurrency, timeouts and data paths here instead of digging through
the code.
"""
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
FINGERPRINTS_DIR = DATA_DIR / "fingerprints"
OUTPUT_DIR = ROOT_DIR / "output"
RAW_SNAPSHOTS_DIR = OUTPUT_DIR / "raw"  # raw HTML/headers saved per domain (useful for debugging + re-running the matcher without re-crawling)

DOMAINS_CSV = DATA_DIR / "domains.csv"

# --- Crawler ---
HTTP_TIMEOUT_SECONDS = 12.0
MAX_CONCURRENT_REQUESTS = 25          # polite, but enough to get through 200 domains in a few minutes
MAX_REDIRECTS = 8
MAX_HTML_BYTES = 3_000_000            # don't keep pages of tens of MB for nothing

# DECISION: matching CSS selectors (the "dom" rules) is a soupsieve tree
# walk per selector, and the database has ~1800 selectors. On a normal page
# (a few tens of KB) that's negligible; on a huge e-commerce page (e.g.
# disneystore.com/halloween-shop is 2.4MB of HTML, a huge product grid) I
# caught the process stuck for minutes on ONE selector, on ONE page -
# confirmed with Ctrl+C + traceback. Above this threshold we skip ONLY the
# "dom" signal for that page (the other signals - headers/cookies/meta/
# html/scriptSrc - are unaffected; they're plain regex and scale linearly
# with size, so they don't have this problem).
MAX_HTML_BYTES_FOR_DOM_MATCHING = 500_000
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
    "VeridionTechScraper/0.1 (+contact: robert)"
)
RETRY_ATTEMPTS = 2

# DECISION: after the full crawl over all domains is done, we do one extra
# pass ONLY over the domains that failed for a reason that looks transient
# (5xx, timeout, connection refused) - not over the ones with no DNS record
# at all, which are almost certainly dead domains. I confirmed manually
# (separate curl, minutes later) that at least 2 of the 12 domains that
# initially failed responded normally a bit later - so a later retry can
# actually recover real domains.
RETRY_PASS_DELAY_SECONDS = 5.0

# DECISION: many technologies only live on internal pages (reCAPTCHA/forms
# on /contact, ecommerce on /shop or /cart, comments on /blog, etc.), not on
# the homepage. We crawl a few extra pages from the same domain instead of
# using a headless browser (much higher cost, see README for why I chose NOT
# to do that on this dataset).
# DECISION: I went from 2 to 3 pages + added new keywords (careers/jobs ->
# often an external ATS like Greenhouse/Lever/Workable; faq/support -> chat
# widgets; signup/register -> auth flows other than login) after seeing the
# number of unique technologies settle around ~300/477 across several runs
# in a row - a sign we'd hit the ceiling of what homepage + 2 "obvious"
# pages can find. That increase is cheap (still no headless browser) and
# targets exactly the pages where technology categories we don't see at
# all yet tend to show up.
# DECISION: tried 3 (instead of 2) - it moved the number of unique
# technologies by exactly 1 (299->300), but tripled matching time (from
# seconds to ~15 minutes over the 200 domains, because of CSS selectors run
# on many more pages). Not worth the tradeoff on this dataset - we stopped
# at 300/477, a real plateau, not a tuning problem. Back to 2 pages, but we
# keep the new keywords (careers/faq/signup etc.) - they cost nothing extra,
# they only change the PRIORITY of the links tried when the homepage has
# such links.
EXTRA_PAGES_PER_DOMAIN = 2
INTERNAL_LINK_CANDIDATES_TO_TRY = 10   # try up to this many links to find EXTRA_PAGES_PER_DOMAIN valid ones
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
