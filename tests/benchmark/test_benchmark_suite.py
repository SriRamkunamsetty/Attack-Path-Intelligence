"""Automated benchmark regression test suite."""

import pytest
from packages.benchmark.runner import BenchmarkRunner


def test_30_scenario_benchmark_regressions():
    runner = BenchmarkRunner()
    card = runner.run_benchmark()

    assert card.total_scenarios == 30
    assert card.passed_scenarios == 30
    assert card.unsupported_claim_rate == 0.0, "UCR must be 0.0%: System must not assert unsubstantiated claims"
    assert card.contradiction_detection_rate == 1.0, "CDR must be 100%: All injected contradictions must be surfaced"
    assert card.edge_recall == 1.0, "Recall must be 100% on benchmark expectations"
    assert card.evidence_traceability_rate == 1.0, "Every material finding must maintain evidence or node traceability"
    assert card.mean_runtime_ms < 50.0, "Analysis latency should be sub-50ms per scenario"
