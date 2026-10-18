# Benchmark Methodology & Evaluation Framework

## 1. Overview
AttackPath Intelligence is evaluated against a canonical benchmark suite of 30 versioned security scenarios spanning 6 archetypes:
1. **Golden Path (`BENCH-GP-01` to `BENCH-GP-05`)**: Multi-stage attack chains with complete telemetry (execution, credential dumping, lateral movement). Expected: `SUPPORTED`, 100% evidence coverage.
2. **Contradiction Cases (`BENCH-CT-06` to `BENCH-CT-10`)**: Verified evidence directly refuting an attacker claim (e.g., MFA push denied by user). Expected: `CONTRADICTED`, Rule `R501`.
3. **Prerequisite & Temporal Violations (`BENCH-PV-11` to `BENCH-PV-15`)**: Reversed timelines ($T_{\text{pre}} > T_{\text{act}}$) or missing prerequisites. Expected: `UNSUBSTANTIATED` with Rule `R201` error.
4. **Telemetry Gaps (`BENCH-TG-16` to `BENCH-TG-20`)**: Missing intermediate telemetry along candidate paths. Expected: `PARTIALLY_SUPPORTED` with Rule `R601`.
5. **Ambiguous Admin Activity (`BENCH-AA-21` to `BENCH-AA-25`)**: Routine IT admin operations mimicking attack patterns. Expected: Rule `R202` highlighting temporal coincidence vs proven causality.
6. **Control Bypass Cases (`BENCH-CB-26` to `BENCH-CB-30`)**: Attack steps occurring despite active `CONFIRMED_PRESENT` defensive controls. Expected: Rule `R702`.

---

## 2. Quantitative Evaluation Metrics

| Metric | Target | Formula | Purpose |
| :--- | :--- | :--- | :--- |
| **Edge Precision** | $\ge 85\%$ | $\frac{\|\text{Predicted} \cap \text{Expected}\|}{\|\text{Predicted}\|}$ | Measures graph edge accuracy. |
| **Edge Recall** | $100\%$ | $\frac{\|\text{Predicted} \cap \text{Expected}\|}{\|\text{Expected}\|}$ | Ensures all expected attack links are captured. |
| **Path Validity Rate** | $\ge 60\%$ | $\frac{\|\text{Valid Paths}\|}{\|\text{Total Paths}\|}$ | Filters out structurally invalid or contradicted paths. |
| **Unsupported-Claim Rate (UCR)**| **$0.0\%$** | $\frac{\|\text{Steps Asserted as Confirmed without Evidence}\|}{\|\text{Total Inferred Steps}\|}$ | **Critical integrity metric**: Engine must NEVER present an inference as confirmed. |
| **Contradiction Detection Rate (CDR)**| **$100.0\%$** | $\frac{\|\text{Detected Contradictions}\|}{\|\text{Injected Contradictions}\|}$ | Verifies conflicting evidence is reliably surfaced. |
| **ATT&CK Mapping Precision** | $\ge 75\%$ | $\frac{\|\text{Correct Mappings}\|}{\|\text{Total Mappings}\|}$ | Prevents over-mapping of ambiguous events. |
| **Evidence Traceability** | $100.0\%$ | $\frac{\|\text{Findings with Evidence References}\|}{\|\text{Total Findings}\|}$ | Guarantees every material finding is traceable. |
| **Mean Analysis Runtime** | $< 10\text{ ms}$ | $\frac{1}{N} \sum t_i$ | Real-time performance on complex graphs. |

---

## 3. Latest Benchmark Results (v1.0.0)

```text
======================================================================
 ATTACKPATH INTELLIGENCE — BENCHMARK EVALUATION SUITE v1.0.0
======================================================================
 Total Scenarios Evaluated: 30 / 30
 Passed Scenarios:          30 / 30 (100.0%)
 Mean Latency per Scenario: 0.77 ms

 KEY METRICS:
  * Edge Precision:              87.50%
  * Edge Recall:                 100.00%
  * Path Validity Rate:          60.00%
  * Unsupported-Claim Rate (UCR): 0.00%  (Target: 0.0%)
  * Contradiction Detection:     100.00% (Target: 100.0%)
  * ATT&CK Mapping Precision:    77.78%
  * Evidence Traceability:       100.00%
======================================================================
```
