"""
Writes the results in the formats the task asks for: JSON (structured,
with evidence) and a "flat" CSV (easy to open in Excel/Sheets, one row per
domain-technology pair - handy for quickly counting how many unique
technologies were found in total, to compare against the 477 mentioned in
the task).
"""
from __future__ import annotations

import csv
import json
from dataclasses import asdict

from src import config
from src.models import Detection


def write_results(results: dict[str, list[Detection]]) -> None:
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    json_payload = {
        domain: [asdict(d) for d in detections]
        for domain, detections in results.items()
    }
    with open(config.RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2, ensure_ascii=False)

    with open(config.RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "technology", "categories", "confidence", "evidence_count", "evidence_summary"])
        for domain, detections in results.items():
            for d in detections:
                evidence_summary = " | ".join(f"{e.signal_type}:{e.matched_value[:60]}" for e in d.evidence)
                writer.writerow([domain, d.technology, ";".join(d.categories), f"{d.confidence:.2f}", len(d.evidence), evidence_summary])

    total_unique_techs = len({d.technology for detections in results.values() for d in detections})
    total_detections = sum(len(v) for v in results.values())
    domains_with_zero = sum(1 for v in results.values() if len(v) == 0)

    print(f"[output] {config.RESULTS_JSON}")
    print(f"[output] {config.RESULTS_CSV}")
    print(f"[summary] domains processed: {len(results)}")
    print(f"[summary] unique technologies found (across the whole set): {total_unique_techs}  (Veridion target: 477)")
    print(f"[summary] total detections (domain, technology): {total_detections}")
    print(f"[summary] domains with 0 technologies detected: {domains_with_zero}")
