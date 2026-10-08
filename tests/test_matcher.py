"""
Tests for matcher.py.

No real HTTP requests here (slow, flaky, internet-dependent) - instead we
build synthetic RawSite objects with exactly the signals we want to test
and check that the matcher picks them up.
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
