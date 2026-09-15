# Cost Model Calibration

How to produce trustworthy `ContractCostType` cost model parameters for
`budget.rs`, and how to know when you have.

This document was written while calibrating the ML-DSA (CAP-0087) cost types,
and uses them as the worked example throughout. The method generalizes; the
ML-DSA-specific decisions are marked as such.

---

## 0. The governing principle

**The fitted model is the source of truth. Never add a bespoke number to it.**

Whatever the calibration procedure produces goes into `budget.rs` verbatim. No
safety multipliers, no hand-rounding, no post-hoc headroom — not even one
derived from a real physical property of the primitive.

The reasons, in order of importance:

1. **Reproducibility.** The committed number must be recoverable by re-running
   the documented procedure. If the table says 692,143 and the bench says
   685,661, the delta lives only in a comment and rots.
2. **Consistency.** Every other cost type in `budget.rs` is a raw fit
   (`Bn254G1Msm = 1185193`, `Bls12381Pairing = 10558948`). A padded entry is
   silently on a different footing from its neighbours.
3. **Accuracy.** Padding trades a symmetric approximation error for a larger
   one-sided error. That is a worse estimator, and conservatism belongs at the
   limits/budget layer, not baked into a coefficient.

If the model looks wrong, **fix the model** — the sample generation, the input
range, the anchor point, the sweep alignment — rather than correcting its
output. If a real limitation remains after that, **document it** (§8); do not
paper over it.

The one place worst-case selection is legitimate is the constant models, where
the procedure itself is defined as "take the max over N samples" (§4.2). That is
the estimator, not a correction applied to one.

---

## 1. Environment

Instruction counts, not wall time, are what feed the models. On Linux,
`soroban-bench-utils` reads them through `perf_event`
(`soroban-bench-utils/src/tracker.rs`), which needs relaxed perf permissions:

```bash
sudo sysctl -w kernel.perf_event_paranoid=1     # reverts on reboot
cat /proc/sys/kernel/perf_event_paranoid        # expect 1
```

Without this, `InstructionCounter::new()` panics on
`perf_event::Builder::new().build()`. Verify before a long run.

Because the measurement is an instruction count, CPU frequency scaling and the
`powersave` governor do **not** affect results — only how long the run takes.
Counts are still microarchitecture- and codegen-dependent, so record the CPU
model alongside the results and treat a laptop run as provisional relative to a
reference host.

Build once, then invoke the binary directly — it is far faster than going
through `cargo bench` for repeated runs:

```bash
cargo bench --features bench --bench worst_case_linear_models --no-run
cargo bench --features bench --bench variation_histograms     --no-run
BIN=./target/release/deps/worst_case_linear_models-<hash>
```

---

## 2. How the harness actually behaves

Read this before designing a sweep. Several behaviours are load-bearing and
none of them are obvious from the outside.

### 2.1 The measurement equation

`benches/common/measure.rs` documents the model as

```
g(x) = N_r * (f(x) + Overhead_b + Overhead_s)
```

`f(x)` is the target cost. `N_r` is `CostRunner::RUN_ITERATIONS`. `Overhead_b`
is bench-setup overhead, removed by the separately-measured baseline.
`Overhead_s` is per-sample overhead, reported by
`get_insns_overhead_per_sample` and non-zero only for wasm-instruction
calibration.

`preprocess()` subtracts the baseline and *then* divides by the tracker's
iteration count. Both sides are `N_r`-scaled, so the order is correct.

### 2.2 The fitter pins the line through the first point — it does not discard it

This is the single most important thing to understand. In
`benches/common/modelfit.rs`:

```rust
let x0 = x.get(0).unwrap();  let y0 = y.get(0).unwrap();
let a = x.iter().map(|x| x - x0);     // least squares on differences
let b = y.iter().map(|y| y - y0);     // -> solves for the slope only
let lin_param = lsq_res.solution[0];
let const_param = y0 - lin_param * x0;   // intercept fixed by point 0 alone
```

The first sample is the **highest-leverage point in the sweep**: it alone
determines `const_term`. Nothing is thrown away.

The design intent is stated in the code, and it is sound:

> `x0` is not necessary equal to 0. Often times it is unrealistic to build a
> sample with input at exactly zero (e.g you can't deserialize a zero byte
> blob to XDR). Here we try to pin it to the lowest point to ensure the
> y-intercept of the produced curve is sane.

Consequences for sweep design:

- **Choose the anchor deliberately.** It should be the lowest *meaningful*
  point in the real input space — low enough that extrapolating to `x=0` is
  short, but not so low that it hits a degenerate or short-circuiting code
  path.
- **If `x=0` is a legitimate, non-degenerate input, use it.** Then
  `const_param = y0` exactly and the constant term is a *directly measured*
  quantity with zero extrapolation. This is strictly better than extrapolating.
- **The anchor's noise propagates 1:1 into `const_term`,** undamped by the rest
  of the sweep. This is the main argument for a high `RUN_ITERATIONS` (§2.5).
- **`x0` is `x[0]`, not `min(x)`.** The code comment assumes the input range is
  monotonically increasing and does not check it. Make sure your sample
  generator is monotonic in the sweep index.

### 2.3 Constant models take the mean and report R² = 0

Also in `fit_model`:

```rust
let const_model = inputs.iter().collect::<HashSet<_>>().len() == 1;
if const_model {
    let const_param = outputs.iter().sum::<u64>() as f64 / outputs.len() as f64;
    return FPCostModel { const_param, lin_param: 0.0, r_squared: 0.0 };
}
```

If every input is identical the fit is bypassed entirely: the constant term is
the **mean**, and `r_squared` is hardcoded to `0.0` ("we are always predicting
the mean").

So an R² gate **cannot** be applied to constant cost types, and an R² of 0 on
one is not a failure. This is an independent reason constant types go through
`variation_histograms` instead (§4.2).

### 2.4 Two silent behaviours to watch for

- **Negative-intercept fallback.** If `const_param < 0` the fitter discards the
  solution, refits constrained through the origin, sets `const_term = 0`, and
  prints `negative intercept detected, will constrain the solution to pass
  through (0,0) and rerun`. Always grep the raw output for that string.
- **Rounding is always up.** `truncate_noise_digits` rounds to 6 decimal places
  with `.ceil()`, then `MeteredCostComponent::from` applies `const_param.ceil()`.

### 2.5 `RUN_ITERATIONS` averages measurement noise, not sample variance

In `harness()`:

```rust
let samples = (0..repeat_iters).map(|_| sample.clone()).collect();
```

One sample is **cloned** `N_r` times. So `RUN_ITERATIONS = 100` measures the
same key/message 100 times. It suppresses measurement noise; it does **not**
explore sample diversity. Diversity across a linear sweep comes from each input
size drawing a fresh sample, and for constant types from
`variation_histograms` running N independent draws.

Sample construction happens *before* `ht.start()`, so cloning cost is outside
the measured region.

### 2.6 `RUN_ITERATIONS` is one const shared by both benches

`RUN_ITERATIONS` is an associated const on the `CostRunner` impl, used by both
benches. The two want opposite values: the linear sweep wants 100 (average out
noise), the histogram wants 1 (each sample must be measured individually or the
variation it exists to measure is averaged away).

**Resolution:** patch `measure_costs_inner` in `benches/common/measure.rs` to
accept an env override, defaulting to the const:

```rust
let iters = std::env::var("RUN_ITERATIONS")
    .ok().and_then(|v| v.parse::<u64>().ok())
    .unwrap_or(<HCM::Runner as CostRunner>::RUN_ITERATIONS);
```

One build then serves both benches with no source edits between runs.

### 2.7 What `variation_histograms` actually samples

`variation_histograms.rs` calls
`measure_cost_variation::<HCM>(sample_count, || 10, || 10, false)`, and
`measure_cost_variation` dispatches:

```
i == 1       => new_random_case(host, rng, 10)   // include_best_case = false
i == 2       => new_worst_case(host, rng, 10)    // exactly one
i in 3..=n   => new_random_case(host, rng, 10)
```

So it is overwhelmingly random cases with **exactly one** worst case. Overriding
`new_worst_case` injects a single adversarial sample into the run — enough for
it to claim the reported `max` if it genuinely is the worst, but far too thin to
quantify a gap. To characterise a worst case properly, point `new_random_case`
at the adversarial constructor for a dedicated run (§6.4).

Note `variation_histograms`'s `Benchmark::bench` returns `Ok(Default::default())`
— it prints histograms and produces no fitted model. The numbers are read from
its printed output.

### 2.8 Determinism and env knobs

Both benches seed `StdRng::from_seed([0xff; 32])`, so a rerun on the same
machine reproduces the same samples. Repeated runs therefore measure
*measurement* noise, not sample variance.

| Variable | Bench | Effect |
|---|---|---|
| `FLOOR`, `RANGE` | linear | sweep index range, default `0..20` |
| `SAMPLE_COUNT` | histogram | number of samples, default 1000 |
| `RUN_ITERATIONS` | both | `N_r` override (§2.6, after patching) |
| `CHECK_RANGE_AGAINST_BASELINE` | both | assert max ≥ 10× baseline |
| `WRITE_PARAMS` | linear | emit pasteable `budget.rs` code |
| `SKIP_WASM_INSNS` | linear | skip the wasm instruction sweep |
| `RUN_EXPERIMENT` | both | use the experimental cost type set |
| `INCLUDE_ANALYTICAL_COSTTYPES` | linear | include MemAlloc/MemCpy/MemCmp |

Bare (non-`-`-prefixed) trailing args filter by cost type name.

### 2.9 Units

`ScaledU64` linear terms are scaled by `2^COST_MODEL_LIN_TERM_SCALE_BITS`, and
`COST_MODEL_LIN_TERM_SCALE_BITS = 7`, i.e. **128**. So `ScaledU64(6101)` means
`6101/128 = 47.66` cost units per input unit. At runtime,
`MeteredCostComponent::evaluate` charges
`const_term + (lin_term * input).unscale()`, so `input = 0` bills exactly
`const_term`.

---

## 3. Pre-calibration audit

Do this before running anything. Each item has bitten a real calibration.

### 3.1 The runner must execute only the region the charge covers

Trace from the `charge_budget` call to the end of the work it pays for, and
confirm the runner's `run_iter` executes that and nothing else.

- Input decoding charged under a *separate* cost type must not run inside the
  runner for the downstream type. Pre-decode it in the sample.
- Confirm the library does not silently redo the earlier work. For ML-DSA,
  `VerifyingKey::decode` → `new_expand_a` performs the SHAKE-128 `A_hat`
  expansion and `t1_2d_hat` precompute, and `raw_verify_mu` only *reads*
  `precomputed_values` — no re-expansion, so decode and verify do not
  double-count.
- The `charge_budget` call itself is inside the measured region, but it is also
  inside the baseline, so it subtracts out.

### 3.2 Samples must be random, seeded, and cover the real input range

- Seeded RNG (`StdRng::from_seed`) so runs are reproducible.
- For crypto, `random seed -> keygen -> sign/encrypt` is an acceptable
  generator; do not enable RNG features just to randomize.
- **The input range must match reality.** A sweep over 1–10 bytes when real
  inputs are ~1000 is a broken calibration even with a perfect R².
- Ask the user for the realistic range if it is not obvious from the call
  sites. Record the answer and its rationale.

### 3.3 The worst case must be demonstrated, not assumed

`HostCostMeasurement::new_worst_case` **defaults to `new_random_case`**. Left
alone, that default is a silent assertion that random sampling reaches the most
expensive input — which is frequently false, and is never free to assume for a
cost type charged *before* the work it pays for.

For every cost type, determine whether the charged region has data-dependent
work at all. If it does:

1. **Identify the parameter** the cost depends on, and its ceiling (usually a
   protocol or format constant).
2. **Measure cost as a function of that parameter**, including both extremes.
   Do not reason it out — where two terms trade off against each other (a scan
   over the unused portion versus work over the used portion, say),
   monotonicity is genuinely not obvious and can go either way.
3. **Measure how often random sampling reaches the ceiling.** If it hits it with
   reasonable probability at the planned sample count, random sampling is
   adequate — but state the measured probability rather than hoping.
4. **If random sampling does not reach the ceiling, override `new_worst_case`**
   with a constructed worst case. Prefer a genuinely valid input obtained by
   rejection search; fall back to a synthetic one only to pin a ceiling that
   search cannot reach, and only where the cost provably depends on structure
   alone rather than validity.

Two practical notes:

- `new_worst_case` is called **once** per `variation_histograms` run (sample #2,
  §2.7) but **once per sweep point** in `worst_case_linear_models`. If
  construction is expensive, cache it in a `OnceLock` so the linear bench does
  not pay for it 241 times.
- A constructed worst case is only meaningful if it still passes whatever
  validation the charged region performs — otherwise it takes an early-exit
  path and is *cheaper*, not more expensive.

Record the resulting cost-versus-parameter curve in the write-up; it is the
evidence that the reported worst case is one.

Worked example: ML-DSA `Signature::decode` in §5.6 and §6.4 — hint weight is the
parameter, ω the ceiling, cost was measured to be monotonically increasing in
it, and honest signing was measured to reach ω often enough (0.10–0.70% of
signatures) that random sampling at n=10,000 finds it.

### 3.4 The baseline must be a true baseline

`new_baseline_case` is run through `run_baseline`, which should perform *only*
the metering call — no real work. It captures host setup plus budget machinery,
and is subtracted from every data point.

If a cost type has additional unavoidable setup noise that scales with
iterations, it must be represented here (or in
`get_insns_overhead_per_sample`), otherwise it leaks into `const_term`.

Enable `CHECK_RANGE_AGAINST_BASELINE=1`: it asserts `max >= 10 * baseline` for
cpu, mem and time, and fails the run otherwise. A cost type whose memory model
is legitimately zero will not false-trip it (`0 < 0` is false).

### 3.5 Write down every special treatment in the fitting

Anything the fitter does that is not "least squares over all points" belongs in
the results write-up: first-point pinning, the constant-model mean branch, the
negative-intercept fallback, the always-up rounding.

---

## 4. The protocol

| | **Linear models** | **Constant models** |
|---|---|---|
| Bench | `worst_case_linear_models` | `variation_histograms` |
| `RUN_ITERATIONS` | 100 | 1 |
| Samples | one per sweep point | 10,000 |
| Reported value | fitted `const_term` + `lin_term`, verbatim | **max** |
| Acceptance gate | R² ≥ 0.99 | CV < 0.5% **and** max/min < 1.01 |
| R² meaningful? | yes | no — hardcoded 0 (§2.3) |

### 4.1 Linear models

1. Choose the anchor (first sweep point) per §2.2.
2. Choose the top of the sweep to match the realistic maximum input.
3. Choose a step size that avoids aliasing against internal block structure
   (§5.3).
4. `RUN_ITERATIONS=100` to average measurement noise, especially at the anchor.
5. Require **R² ≥ 0.99**. If it is not reached, do not proceed — diagnose.
   Common causes: the cost is not actually linear in the declared input; the
   input range straddles an algorithmic regime change; the runner is executing
   work outside the charge region; the sweep aliases against a step structure.

### 4.2 Constant models

1. `SAMPLE_COUNT=10000`, `RUN_ITERATIONS=1`.
2. Inspect `min`, `max`, `max/min`, `mean`, `std` from the histogram output.
3. Require **CV = std/mean < 0.5%** and **max/min < 1.01**. If the spread
   exceeds this, raise the sample count; if it still fails, the constant-model
   assumption is wrong and the cost type needs rethinking (it probably has a
   hidden input).
4. **Report the max**, not the mean. With the variance gate satisfied, the max
   is close to the mean by construction.
5. If the cost has a data-dependent component with an adversarial worst case
   that random sampling may not reach, construct that case explicitly and
   measure it (§6.4).

---

## 5. ML-DSA-specific decisions and rationale

### 5.1 Context string fixed at 0

The charged input is `msg.len() + ctx.len()`, and SHAKE-256 absorbs
`tr || 0x00 || len(ctx) || ctx || M`. The absorbed length is therefore
`66 + (msg + ctx)` regardless of how the total is split between the two, so
context and message bytes are interchangeable byte-for-byte by construction.
Calibrate with `ctx = 0` (the common real case).

If this is ever tested empirically, note that comparing a `ctx > 0` measurement
against the *fitted line* is invalid: the line only touches the true staircase
at the phases it was sampled at, so a point at an unsampled phase differs from
it by up to half a block, which has nothing to do with the context. A valid test
holds the total `x` fixed and varies only the split -- e.g. measure
`(ctx = 0, msg = 255)` against `(ctx = 255, msg = 0)`, which share both `x` and
absorbed length -- and compares the two measurements directly.

### 5.2 Anchor at x = 0

With `ctx = 0, msg = 0` the charged input is `x = 0`, so
`const_term = y(0)` — directly measured, no extrapolation.

This is a legitimate, non-degenerate sample: SHAKE still absorbs 66 bytes
(`tr`(64) `|| 0x00 || len(ctx)=0x00`), runs a full permutation, and the entire
lattice verification proceeds. Nothing short-circuits. (Contrast a cost type
like XDR deserialize, where a zero-length input *is* degenerate and the anchor
must be moved up.)

Note it is 66 bytes, not 64 — which is what places the first block boundary at
`x = 70`.

### 5.3 Step size = 136 bytes (the SHAKE-256 rate)

The true cost is **not affine — it is a staircase.** SHAKE-256 has a 136-byte
rate, and absorption costs one Keccak-f[1600] permutation per block, so the
permutation count is `floor((66 + x)/136) + 1`.

Sampling at multiples of 136 places every sweep point at an identical phase
within its block, so each point advances by exactly one permutation:

```
     x  blocks   phase
     0       1   (first block)
   136       2   66 of 136
   272       3   66 of 136
   408       4   66 of 136
```

This removes the staircase from the residuals and drives R² toward 1.0, leaving
measurement noise as the only error term — which is what `RUN_ITERATIONS=100`
then targets.

**It also removes the staircase from the diagnostics**, which is why a
deliberately non-aligned control sweep is mandatory (§6.2).

### 5.4 Sweep range: 0 to ~32 KB

`INPUT_BASE_SIZE = 0`, `STEP_SIZE = 136`, `FLOOR=0`, `RANGE=241`
→ x = 0, 136, ..., 32,640.

Chosen to cover realistic signed payloads, from a 32-byte `__check_auth` hash up
to bulk application data.

### 5.5 The residual staircase error is documented, not corrected

The fitted line under-charges by at most ~0.46% of `const_term` where a real
input lands just past a block boundary, and over-charges by a similar amount
just before one. This is the irreducible error of representing a step function
with a line.

Per §0 this is **not** corrected in the number. It is recorded in §8 of the
results.

The same staircase exists in every hash-linear cost type already in the table
(`ComputeSha256Hash`, `VerifyEd25519Sig`, `Bls12381HashToG1`), none of which
carry any correction.

### 5.6 Decode worst cases

`VerifyingKey::decode` — no construction needed. Its variance comes from
rejection sampling in the SHAKE-128 `A_hat` expansion, which averages over
`k*l*256` coefficients and concentrates hard (measured max/min = 1.0006).
Random sampling is adequate, and there is no way to construct a worst case
short of searching over `rho`.

`Signature::decode` — needs an explicit worst case. It performs **no
cryptography**; the only data-dependent work is `Hint::bit_unpack`:

- `decode_z` is `BitPack::unpack` over fixed-size arrays — data-independent.
- `infinity_norm` uses constant-time `ct_gt`/`ct_select` with no early exit —
  data-independent.
- `bit_unpack` scans `indices[max_cut..]` (length `omega - max_cut`) and then
  performs `max_cut` bounded writes with strictly-increasing checks. The two
  terms trade off, so **monotonicity in hint weight is not obvious and must be
  measured, not assumed.**

Because decode contains no cryptography, a cryptographically valid signature and
a merely structurally-valid one cost **identically at equal hint weight**. A
valid signature is therefore the correct target and the more defensible one — it
requires no argument about reachability. Crafting buys exactly one thing:
deterministic control over the hint weight.

The charge is levied *before* decode, so the adversarial input class is real: an
attacker submits bytes that decode successfully and fail verification
afterwards, having paid only the decode cost. Malformed signatures return `None`
early and are *cheaper*, so they are not the worst case.

---

## 6. Experiments

Retain the raw stdout+stderr of every run, plus the synthesized tables.

### 6.1 E1 — Linear production sweep

```bash
RUN_ITERATIONS=100 CHECK_RANGE_AGAINST_BASELINE=1 \
FLOOR=0 RANGE=241 \
$BIN VerifyMlDsa44Sig VerifyMlDsa65Sig VerifyMlDsa87Sig --nocapture \
  > calibration-ml-dsa-linear.txt 2>&1
```

Requires `INPUT_BASE_SIZE = 0`, `STEP_SIZE = 136`, `CTX_LEN = 0` on the
measurement impls. Produces the committed `const_term` and `lin_term`.

**Pass:** R² ≥ 0.99 on all three; no `negative intercept detected`.

### 6.2 E2 — Non-aligned control sweep (model validity)

```bash
RUN_ITERATIONS=100 FLOOR=0 RANGE=40 \
$BIN VerifyMlDsa44Sig VerifyMlDsa65Sig VerifyMlDsa87Sig --nocapture \
  > calibration-ml-dsa-linear-unaligned.txt 2>&1
```

With `STEP_SIZE = 1024` (not a multiple of 136), the staircase reappears in the
residuals. Compute residuals against the fitted line and confirm their
peak-to-peak amplitude matches `lin_term * 136`.

**Pass:** the two agree within ~10%. They are independent estimates — one from
the fit's signal, one from its error — so agreement is real evidence the block
model is correct. Disagreement means the assumed structure is wrong and E1's
alignment is invalid.

### 6.3 E3 — Constant model histograms

```bash
RUN_ITERATIONS=1 SAMPLE_COUNT=10000 CHECK_RANGE_AGAINST_BASELINE=1 \
$HIST MlDsa44DecodeVerifyingKey MlDsa65DecodeVerifyingKey MlDsa87DecodeVerifyingKey \
      MlDsa44DecodeSignature MlDsa65DecodeSignature MlDsa87DecodeSignature \
      --nocapture > calibration-ml-dsa-variation.txt 2>&1
```

Extract to CSV with
`~/.claude/skills/extract-calibration-for-const-models/extract_calibration.py`.

**Pass:** CV < 0.5% and max/min < 1.01 for all six. Report the max.

### 6.4 E4 — Hint weight experiment (throwaway, not checked in)

Kept out of the repo; lives in the scratchpad.

1. **Distribution.** Sign N random messages per variant, parse the hint weight
   from the encoding (the last of the K `cuts` bytes is the cumulative total),
   and histogram it. Establishes the maximum weight honest signing reaches and
   how often.
2. **Cost vs weight.** Measure decode cost at weight 0, `omega/2`, and `omega`,
   plus a spread-across-polynomials layout at each. Establishes the *direction*
   of the dependence rather than assuming it (§5.6).
3. **Gap.** Run a histogram with `new_random_case` temporarily pointed at the
   worst-case constructor so all 10,000 samples are worst-case, and compare the
   full distribution against E3's honest one. Repeat a few times for stability.

Outputs feed §8 of the results. Only the conclusion is checked in.

---

## 7. Applying and verifying results

1. Paste the fitted values into `budget.rs` verbatim (`WRITE_PARAMS=1` emits
   pasteable code). Remove any `TODO: calibrate` comment the entries carried.
2. Re-record the affected snapshots — `src/test/budget_metering.rs` carries
   hardcoded expectations that will move, as do observation files.
3. Re-run the full test suite across the feature matrix.
4. `cargo fmt --all` and CI-strength clippy.

---

## 8. What the results write-up must contain

- Machine: CPU model, `perf_event_paranoid` value, toolchain version, commit SHA.
- The exact commands and env vars for every run.
- Raw output files, retained.
- Per cost type: fitted or max value, R² (linear) or CV and max/min (constant),
  and the sample count.
- Every special fitting treatment that applied (§3.5).
- Known model limitations, stated plainly and left uncorrected:
  - the linear-vs-staircase approximation error and its bound;
  - any worst case that was bounded analytically rather than measured;
  - the hardware caveat if not run on a reference host.

---

## 9. Checklist

```
[ ] perf_event_paranoid relaxed; verified
[ ] Audit: runner covers only the charged region
[ ] Audit: library does not redo work charged under another cost type
[ ] Audit: samples seeded, random, realistic range confirmed with the user
[ ] Audit: worst case demonstrated; new_worst_case overridden if random misses it
[ ] Audit: baseline performs only the metering call
[ ] Anchor point chosen deliberately and justified
[ ] Sweep top matches the realistic maximum input
[ ] Step size checked for aliasing against internal block structure
[ ] RUN_ITERATIONS=100 (linear) / 1 (histogram)
[ ] CHECK_RANGE_AGAINST_BASELINE=1 on
[ ] Raw output greped for "negative intercept detected"
[ ] Linear: R^2 >= 0.99
[ ] Constant: CV < 0.5% and max/min < 1.01 at n=10,000; max reported
[ ] Non-aligned control sweep agrees with the block model
[ ] Adversarial worst cases constructed and measured where applicable
[ ] Values pasted verbatim; no bespoke adjustments
[ ] Snapshots re-recorded; tests, fmt, clippy pass
[ ] Raw outputs and synthesized tables retained
[ ] Limitations documented, not corrected
```
