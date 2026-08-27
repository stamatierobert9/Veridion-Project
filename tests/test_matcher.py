"""
Skeleton de teste pentru matcher.py.

Ideea: nu vrei sa faci request-uri HTTP reale in teste (lent, fragil,
depinde de internet). In loc de asta, construiesti RawSite-uri sintetice
cu exact semnalele pe care vrei sa le testezi si verifici ca matcher-ul
le prinde.

Completeaza-le pe masura ce scrii logica din matcher.py. Cateva cazuri
pe care ar trebui sa le acoperi:
  - un header care se potriveste unei tehnologii cunoscute (ex: server: cloudflare)
  - un cookie caracteristic (ex: __cfduid, PHPSESSID)
  - un <meta name="generator" content="WordPress 6.4"> in HTML
  - un site fara nicio potrivire -> lista goala, nu crash
  - un site cu site.error setat -> lista goala, fara sa incerce sa parseze HTML gol
"""
from src.fingerprints import load_technologies
from src.matcher import detect_technologies
from src.models import RawSite


def test_no_crash_on_empty_site():
    technologies = load_technologies()
    site = RawSite(domain="example.com")
    result = detect_technologies(site, technologies)
    assert isinstance(result, list)


def test_error_site_returns_empty():
    technologies = load_technologies()
    site = RawSite(domain="example.com", error="timeout")
    result = detect_technologies(site, technologies)
    assert result == []


# TODO(Robert): adauga teste pentru cazurile de mai sus din docstring
