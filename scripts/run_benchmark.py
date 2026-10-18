"""CLI script to run the 30-scenario benchmark suite and print a scorecard."""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure repository root is on sys.path
root_dir = Path(__file__).resolve().parents[1]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from packages.benchmark.runner import BenchmarkRunner


def main() -> None:
    print("\n" + "=" * 70)
    print(" ATTACKPATH INTELLIGENCE — BENCHMARK EVALUATION SUITE v1.0.0")
    print(" Evaluating 30 ground-truth cybersecurity reasoning scenarios...")
    print("=" * 70)

    runner = BenchmarkRunner()
    card = runner.run_benchmark()

    # Output directory
    out_dir = Path(__file__).resolve().parents[1] / "data" / "benchmark"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "latest_scorecard.json"

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(card.model_dump(), f, indent=2)

    print(f"\n[+] Execution Completed in {card.mean_runtime_ms * card.total_scenarios:.1f}ms total")
    print(f"[+] Total Scenarios Evaluated: {card.total_scenarios}")
    print(f"[+] Passed Scenarios:          {card.passed_scenarios} / {card.total_scenarios} ({card.passed_scenarios / card.total_scenarios * 100:.1f}%)")
    print("-" * 70)
    print(" KEY EVALUATION METRICS:")
    print(f"  * Edge Precision:             {card.edge_precision * 100:.2f}%")
    print(f"  * Edge Recall:                {card.edge_recall * 100:.2f}%")
    print(f"  * Path Validity Rate:         {card.path_validity_rate * 100:.2f}%")
    print(f"  * Unsupported-Claim Rate (UCR): {card.unsupported_claim_rate * 100:.2f}%  (Target: 0.0%)")
    print(f"  * Contradiction Detection:    {card.contradiction_detection_rate * 100:.2f}% (Target: 100.0%)")
    print(f"  * ATT&CK Mapping Precision:   {card.attack_mapping_precision * 100:.2f}%")
    print(f"  * Evidence Traceability:      {card.evidence_traceability_rate * 100:.2f}%")
    print(f"  * Mean Latency per Scenario:  {card.mean_runtime_ms:.2f} ms")
    print("-" * 70)
    print(" ARCHETYPE BREAKDOWN:")
    for cat, stats in card.category_breakdown.items():
        print(f"  - {cat:<24}: {stats['passed']} / {stats['total']} passed")
    print("=" * 70)
    print(f"[+] Full results exported to: {out_file}\n")


if __name__ == "__main__":
    main()
