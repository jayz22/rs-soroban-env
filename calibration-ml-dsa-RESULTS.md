# ML-DSA Calibration Results

Produced by the protocol in `docs/CALIBRATION.md`.

| | |
|---|---|
| Commit | `21c0665f` (Add NIST ACVP and Wycheproof conformance vectors for ML-DSA) |
| CPU | Intel Core i7-10750H @ 2.60GHz |
| `perf_event_paranoid` | 1 |
| rustc | 1.90.0 (1159e78c4 2025-09-14) |
| Date | 2026-09-15 |

**Provisional**: run on a development laptop, not reference hardware.
Instruction counts port across machines far better than timings, but codegen
differs between microarchitectures.

Bench source changes required (both uncommitted at time of writing):
`benches/common/measure.rs` (the `RUN_ITERATIONS` env override) and
`benches/common/cost_types/ml_dsa.rs` (`CTX_LEN=0`, `INPUT_BASE_SIZE=0`,
`STEP_SIZE=136`, and the `new_worst_case` override on the three
`DecodeSignature` measures).

---

## 1. Calibrated values

### Linear models — E1

```
RUN_ITERATIONS=100 CHECK_RANGE_AGAINST_BASELINE=1 FLOOR=0 RANGE=241 \
  worst_case_linear_models VerifyMlDsa44Sig VerifyMlDsa65Sig VerifyMlDsa87Sig
```

241 points, x = 0 … 32,640 bytes in 136-byte steps, 100 iterations each.

| cost type | cpu const | cpu lin | R² | mem const | mem lin |
|---|---|---|---|---|---|
| `VerifyMlDsa44Sig` | 685,165 | `ScaledU64(6103)` | 0.99999998 | 0 | 0 |
| `VerifyMlDsa65Sig` | 983,619 | `ScaledU64(6103)` | 0.99999998 | 0 | 0 |
| `VerifyMlDsa87Sig` | 1,437,210 | `ScaledU64(6102)` | 0.99999998 | 0 | 0 |

`ScaledU64(6103)` = 6103/128 = 47.68 cpu insns per byte of `msg + ctx`.
Identical across variants, as expected: the linear term is SHAKE-256
absorption, which does not depend on the parameter set.

Memory R² is `NaN` because every measurement is 0 — verification allocates
nothing, working in place over the already-decoded key and signature.

### Constant models — E3

```
RUN_ITERATIONS=1 SAMPLE_COUNT=10000 CHECK_RANGE_AGAINST_BASELINE=1 \
  variation_histograms MlDsa{44,65,87}Decode{VerifyingKey,Signature}
```

Reported value is the **max**, per the protocol.

| cost type | min | **max** | max/min | mean | std | CV | mem |
|---|---|---|---|---|---|---|---|
| `MlDsa44DecodeVerifyingKey` | 848,479 | **849,110** | 1.00074 | 848,904 | 78.4 | 0.009% | 24,656 |
| `MlDsa65DecodeVerifyingKey` | 1,504,569 | **1,505,271** | 1.00047 | 1,505,166 | 142.5 | 0.009% | 43,088 |
| `MlDsa87DecodeVerifyingKey` | 2,624,928 | **2,625,760** | 1.00032 | 2,625,506 | 116.7 | 0.004% | 73,808 |
| `MlDsa44DecodeSignature` | 37,623 | **37,888** | 1.00704 | 37,804 | 47.5 | 0.126% | 4,104 |
| `MlDsa65DecodeSignature` | 47,421 | **47,691** | 1.00569 | 47,550 | 35.2 | 0.074% | 5,128 |
| `MlDsa87DecodeSignature` | 66,058 | **66,346** | 1.00436 | 66,199 | 39.9 | 0.060% | 7,176 |

Gate: CV < 0.5% **and** max/min < 1.01. **All six pass.** Memory is exactly
constant (`min == max`) for all six.

---

## 2. Assumption checks

### E2 — staircase / model validity

Re-ran the sweep deliberately mis-aligned (`STEP_SIZE=1024`, 40 points) so the
136-byte block structure reappears in the residuals.

**Fitted parameters are identical to E1** (685165/6103, 983619/6103,
1437209/6103), confirming the alignment improves residuals without biasing the
fit. R² drops from 0.99999998 to 0.99999, and the residuals form a sawtooth:

| cost type | residual peak-to-peak | `lin × 136` | agreement |
|---|---|---|---|
| `VerifyMlDsa44Sig` | 6,393 | 6,484 | 1.4% |
| `VerifyMlDsa65Sig` | 6,427 | 6,484 | 0.9% |
| `VerifyMlDsa87Sig` | 6,427 | 6,484 | 0.9% |

These are independent estimates of one Keccak-f[1600] permutation — one from
the fit's signal, one from its error. Agreement within 1.4% confirms the block
model. (6,484 / 24 rounds ≈ 270 insns per Keccak round, a plausible figure for
portable non-SIMD Rust.) **Pass.**

### E4 — `DecodeSignature` worst case

Separate throwaway project in `calibration-experiments/` (not committed).
2,000 honest signatures per variant; decode measured directly via `perf_event`,
min of 200 runs.

Cost is **monotonically increasing in hint weight** — the `max_cut` write loop
dominates the `indices[max_cut..]` scan it trades off against. Measured, not
assumed:

| variant | weight 0 | weight ω | delta |
|---|---|---|---|
| ML-DSA-44 | 40,927 | 41,342 | +415 (1.0%) |
| ML-DSA-65 | 50,628 | 50,899 | +271 (0.5%) |
| ML-DSA-87 | 70,786 | 71,170 | +384 (0.5%) |

Honest signing **does reach ω**, so random sampling finds the true worst case:

| variant | ω | honest weight min/max/mean | reached ω | gap: ceiling − honest max |
|---|---|---|---|---|
| ML-DSA-44 | 80 | 43 / 80 / 62.8 | 14/2000 (0.70%) | +15 insns (+0.036%) |
| ML-DSA-65 | 55 | 19 / 55 / 38.3 | 5/2000 (0.25%) | +112 insns (+0.220%) |
| ML-DSA-87 | 75 | 32 / 75 / 56.6 | 2/2000 (0.10%) | −8 insns (−0.011%) |

At n = 10,000 that is ~70 / ~25 / ~10 samples at ω. `new_worst_case` was
nonetheless overridden with a rejection-searched ω-weight signature so the
worst case is guaranteed rather than probable. The E3 max was essentially
unchanged by the override (37,895 at n=1000 before → 37,888 at n=10,000 after),
which independently confirms random sampling was already adequate.

Layout (hints concentrated in one polynomial vs spread across all `k`) changes
cost by ≤ 30 insns — below the noise floor.

---

## 3. Known limitations — documented, not corrected

Per `docs/CALIBRATION.md` §0, the fitted values go in verbatim. These are the
residual inaccuracies that remain.

1. **Linear-vs-staircase approximation.** The true cost is a step function of
   one Keccak-f per 136-byte block. A line through it under-charges by up to
   ~3,150 insns (0.46% of the constant term) for inputs landing just past a
   block boundary, and over-charges by a similar amount just before one. This
   is irreducible for a linear model and is shared by every hash-linear cost
   type already in the table (`ComputeSha256Hash`, `VerifyEd25519Sig`,
   `Bls12381HashToG1`), none of which carry any correction.

2. **`DecodeSignature` hint-weight ceiling** is now measured rather than
   bounded analytically (E4), so no gap remains here.

3. **Hardware.** Development laptop, not a reference host (§ header).

---

## 4. Raw outputs

| file | experiment |
|---|---|
| `calibration-ml-dsa-linear.txt` | E1 — production linear sweep |
| `calibration-ml-dsa-linear-unaligned.txt` | E2 — non-aligned diagnostic |
| `calibration-ml-dsa-variation.txt` | E3 — constant model histograms |
| `calibration-ml-dsa-variation.csv` | E3 — extracted table |
| `calibration-ml-dsa-hint-weight.txt` | E4 — hint weight experiment |
| `calibration-experiments/` | E4 source (throwaway, not committed) |

---

## 5. Status

Applied:

- Values written into `budget.rs` verbatim.
- `src/test/budget_metering.rs` snapshot table updated.
- Observation files required no change. The only ML-DSA observation covers the
  protocol gate, which traps before any ML-DSA cost is charged, so it records
  only the preceding `bytes_new_from_slice` calls. `hostile.rs` records zero
  consumption for these types rather than model parameters, so it is likewise
  unaffected.

Verified:

- `cargo test -p soroban-env-host`: 821 lib tests plus all integration binaries
  pass.
- `cargo fmt --all --check`: clean.
- `cargo hack --each-feature clippy --locked`: exit 0.

Not run to completion:

- `cargo hack --each-feature test --profile test-opt --locked` (the full CI
  feature matrix) was stopped partway. The default-feature suite passes; the
  matrix run should be completed before this is merged.
