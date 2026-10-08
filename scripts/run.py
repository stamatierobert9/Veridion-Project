#!/usr/bin/env python3
"""
CLI entry point.

Usage:
    python scripts/run.py                 # full crawl + detection
    python scripts/run.py --from-cache     # reuse the last raw crawl
                                            # (output/raw/*.json) and only
                                            # re-run the matcher - useful when
                                            # iterating on matcher.py
"""
import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.pipeline import run


def main() -> None:
    parser = argparse.ArgumentParser(description="Veridion Website Technologies Scraper")
    parser.add_argument("--from-cache", action="store_true", help="skip the crawl, use existing raw snapshots")
    args = parser.parse_args()

    asyncio.run(run(use_cache=args.from_cache))


if __name__ == "__main__":
    main()
