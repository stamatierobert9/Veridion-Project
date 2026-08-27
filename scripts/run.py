#!/usr/bin/env python3
"""
CLI de intrare.

Utilizare:
    python scripts/run.py                 # crawl complet + detectie
    python scripts/run.py --from-cache     # refoloseste ultimul crawl brut
                                            # (data/output/raw/*.json) si doar
                                            # re-ruleaza matcher-ul - util cand
                                            # iterezi pe matcher.py
"""
import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.pipeline import run


def main() -> None:
    parser = argparse.ArgumentParser(description="Veridion Website Technologies Scraper")
    parser.add_argument("--from-cache", action="store_true", help="sari peste crawl, foloseste raw snapshots existente")
    args = parser.parse_args()

    asyncio.run(run(use_cache=args.from_cache))


if __name__ == "__main__":
    main()
