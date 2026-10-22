# Calibration report: worst-case fixes + no-AVX2 crypto recalibration

Branch `calibration-fixes`, on top of commit `b9b5dc5b`. 2026-10-21/22.

## 1. Environment

| | |
|---|---|
| CPU | Intel Core i7-10750H (AVX2, BMI2, ADX; no AVX-512, no SHA-NI) |
| OS / kernel | Linux 6.2.0-39-generic, `kernel.perf_event_paranoid = -1` |
| Toolchain | rustc 1.90.0 (stable), cargo profile `release`/`bench` with the repo default `overflow-checks = true`, `lto = true` |
| Build for all measurements | `CARGO_TARGET_DIR=target-serial RUSTFLAGS='-Dwarnings --cfg curve25519_dalek_backend="serial"'` with `--features bench,sha2/force-soft` |
| Metric | CPU instruction counts via `perf_event` (not wall time) |

The build flags turn off the only two runtime-dispatched AVX2 paths in the
host's dependency tree: the `curve25519-dalek` vector backend (Ed25519 point
arithmetic) and `sha2`'s AVX2 SHA-512 compressor (used inside Ed25519 verify).
Verified by `nm` on the built binaries: the default build contains
`curve25519_dalek::backend::vector::avx2::*` and `sha2::sha512::x86::*`
symbols, the serial build contains neither. No other calibrated dependency
(`ark-*`, `k256`, `p256`, `ethnum`, `sha3`) has a SIMD path, so using the one
build for all cost types is harmless and keeps the run consistent.

The `curve25519_dalek_backend` cfg cannot be expressed as a Cargo feature, so
the command must be reproduced as written above; `sha2/force-soft` is an
ordinary dependency feature that can be passed on the command line.

## 2. Review of the worst-case inputs introduced in `b9b5dc5b`

| Cost type(s) | Committed worst case | Verdict | Evidence |
|---|---|---|---|
| `Bls12381G1Mul`, `Bls12381G2Mul`, `Bn254G1Mul` | canonical scalar `< r` with max Hamming weight (254/255 bits for BLS, 253/254 for BN254) | **Agree** | The host calls `Affine::mul` → `P::mul_affine`, which neither curve config overrides, so it is `sw_double_and_add_affine`: one doubling per bit, one mixed add per set bit. Exhaustive check over bit positions confirms the chosen scalars are the max-weight values below `r`. Measured: worst sample = 1.40–1.52× the random samples. |
| `Bn254G1ProjectiveToAffine`, `Bls12381G{1,2}ProjectiveToAffine` | random Jacobian point with `Z ∉ {0,1}` | **Agree, with a limitation** | `into_affine` short-circuits `Z == 1` to a copy; `G1Projective::rand` on BN254 always yields `Z == 1` (cofactor 1), so the old sample never ran the inversion. With `Z ≠ 1` the cost is one field inversion (binary extended Euclid, input-dependent) plus 3 mults. Over 10,000 random `Z`: max/min = 1.19 (BN254 G1), 1.14 (BLS G1), 1.12 (BLS G2). The max over 10k is the committed estimator; a provably worst `Z` for BEA was not constructed. |
| `Int256Shift` | `(I256::MAX, 1)` | **Agree** | Sweep over shift amounts 0–2³²-1 on `MAX`, `MIN`, `1`: results that allocate a new object (e.g. `MAX << 64`, 2,719) are higher only because of the separately-charged `MemAlloc`; among non-allocating results `(MAX, 1)` = `(MIN, 63)` = 2,106 is the max, and the `≥ 256` error path is lower (2,059). |
| `Int256Mul` | `((1<<126)+1, -((1<<64)+1))` — 65-bit divisor | **Disagree → changed** | `imulc` always runs the full `mul3`, then (for both `\|x\| ≥ 2`) one 256-bit division `MAX/\|b\|` or `MIN/-\|b\|`. A divisor with a non-zero high 128-bit word takes `div_mod_knuth` instead of `udiv256_by_128_to_128`. 2-D sweep over divisor width 65–253 bits × multiplicand width × bit pattern × sign (229 pairs): Knuth path with opposite signs = **5,774** vs **5,664** for the committed pair (+1.9%); flat across widths 129–180. New sample: `((1<<124)+1, -((1<<128)+1))`. |
| `Int256Pow` | `(2, u32::MAX)` | **Disagree → changed** | `checked_pow` is square-and-multiply; an all-ones exponent runs at most 2·32−1 = 63 `checked_mul` calls. Base 2 overflows after 15 (14 with the division). Bases 0/±1 run all 63, each a full `mul3` with the division skipped. Measured (200 samples each, worst injected): base 1/−1/0 = **10,293**, base −2 = 9,012, base 2 = 8,228, base 3 = 8,226, base 4 = 7,826. The committed comment had the comparison backwards. New sample: `(1, u32::MAX)`. Host overhead is identical for both (both small-value inputs; result 1 is small, the old overflow path's `host.err` is a plain error construction without debug mode). |

An independent review (subagent, Fable 5.1) re-derived both changes from the
`ethnum` 1.5.3 source and agreed; its only suggestion — pin the "any other
base overflows" claim in the test — was applied.

## 3. Protocol

Per the `calibrating-cost-models` skill:

- Constant models: `variation_histograms`, `RUN_ITERATIONS=1`, `SAMPLE_COUNT=10000`,
  committed value = **max**. One worst-case sample is injected (sample #2) where
  `new_worst_case` is overridden; the others are random. `CHECK_RANGE_AGAINST_BASELINE=1`
  was on except where noted.
- Linear model (`VerifyEd25519Sig`): `worst_case_linear_models`, `RUN_ITERATIONS=100`,
  20 sweep points, message length 1 B → 19,457 B, line pinned through the first point,
  `CHECK_RANGE_AGAINST_BASELINE=1 WRITE_PARAMS=1`. Committed value = fitted
  `const_term`/`lin_term` verbatim.
- Commands, per cost type (`$FEAT=bench,sha2/force-soft`, env as in §1):
  `RUN_ITERATIONS=1 SAMPLE_COUNT=10000 CHECK_RANGE_AGAINST_BASELINE=1 cargo bench -p soroban-env-host --features $FEAT --bench variation_histograms -- <CostType>`
  and `CHECK_RANGE_AGAINST_BASELINE=1 WRITE_PARAMS=1 SKIP_WASM_INSNS=1 cargo bench -p soroban-env-host --features $FEAT --bench worst_case_linear_models -- VerifyEd25519Sig`.

## 4. Results (all values verbatim from the logs; "old" = `b9b5dc5b`)

### Constant cost types (10,000 samples)

| Cost type | old | **new (max)** | Δ | min | mean | max/min | std |
|---|---:|---:|---:|---:|---:|---:|---:|
| `Int256Mul` | 5,058 | **5,771** | +14.1% | 4,537 | 4,544 | 1.272 | 14 |
| `Int256Pow` | 10,777 | **10,293** | −4.5% | 2,758 | 2,837 | 3.732 | 108 |
| `Int256Shift` ¹ | 1,899 | **2,100** | +10.6% | 2,047 | 2,071 | 1.026 | 11 |
| `Bls12381G1Mul` | 3,513,357 | **3,110,211** | −11.5% | 1,944,798 | 2,167,341 | 1.599 | 61,029 |
| `Bls12381G2Mul` | 11,493,513 | **9,836,091** | −14.4% | 6,050,753 | 6,729,283 | 1.626 | 199,704 |
| `Bn254G1Mul` | 1,642,921 | **1,467,330** | −10.7% | 923,157 | 1,024,558 | 1.589 | 28,536 |
| `Bn254G1ProjectiveToAffine` | 34,266 | **34,237** | −0.1% | 28,780 | 31,882 | 1.190 | 655 |
| `Bls12381G1ProjectiveToAffine` | 92,642 | **87,728** | −5.3% | 77,016 | 82,803 | 1.139 | 1,376 |
| `Bls12381G2ProjectiveToAffine` ¹ | 100,742 | **95,662** | −5.0% | 85,681 | 91,191 | 1.116 | 1,382 |
| `ComputeEd25519PubKey` | 40,256 | **44,420** | +10.3% | 44,419 | 44,417 | 1.00002 | 2 |
| `RecoverEcdsaSecp256k1Key` | 2,314,804 | **2,305,375** | −0.4% | 2,293,372 | 2,299,261 | 1.005 | 1,573 |
| `VerifyEcdsaSecp256r1Sig` | 3,000,906 | **2,915,981** | −2.8% | 2,902,877 | 2,909,826 | 1.005 | 1,611 |
| `DecodeEcdsaCurve256Sig` ¹ | 711 | **824** | +15.9% | 824 | 824 | 1.000 | 0 |
| `Sec1DecodePointUncompressed` ¹ | 1,882 | **1,851** | −1.6% | 1,850 | 1,850 | 1.0005 | 0.02 |

¹ Run without `CHECK_RANGE_AGAINST_BASELINE`: `Int256Shift`, `DecodeEcdsaCurve256Sig`
and `Sec1DecodePointUncompressed` are too cheap to clear the 10×-baseline check at
`RUN_ITERATIONS=1`; `Bls12381G2ProjectiveToAffine` tripped the check's *wall-time*
variant only (59,672 ns vs 10× baseline 11,018 ns), not the instruction one.

Memory outputs were constant and unchanged for every type (`RecoverEcdsaSecp256k1Key`
80 B, all others 0), so no `mem` parameters were touched. `Int256Mul` showed a
single 528-byte sample among 10,000 (a random pair whose result allocated);
irrelevant to the CPU model.

### Linear cost type (`VerifyEd25519Sig`)

| | old (AVX2 build, other machine) | **new (no-AVX2)** | Δ |
|---|---:|---:|---:|
| `const_term` | 377,551 | **706,689** | +87.2% |
| `lin_term` | `ScaledU64(4059)` = 31.7 insn/B | **`ScaledU64(4229)`** = 33.0 insn/B | +4.2% |
| R² | — | 0.99932 | |

No "negative intercept" fallback occurred. For reference, the same sweep on the
default (AVX2) build on this machine gave 393,279 / `ScaledU64(4383)`, R² 0.99986,
so the serial backend costs ~1.8× the instructions per verify while the SHA-512
per-byte cost is essentially unchanged.

### Gate assessment

- All types with an injected worst case necessarily fail the "max/min < 1.01"
  constant-model gate — by design, since one adversarial sample sits above a random
  population; the max is the estimator.
- The projective-to-affine types fail it for a real reason: BEA inversion cost is
  input-dependent (spread 12–19%). Random sampling over 10k `Z` values is the
  estimator; the true worst `Z` may be somewhat higher.
- The purely data-independent crypto types (`ComputeEd25519PubKey`, ECDSA, decoders)
  pass comfortably (max/min ≤ 1.005, CV < 0.1%).
- Reproducibility: `RecoverEcdsaSecp256k1Key`, `VerifyEcdsaSecp256r1Sig` and
  `VerifyEd25519Sig` were each measured twice in this session (earlier default-build
  run and this run); maxima agree within 0.02% and the Ed25519 fit is identical to
  the instruction.

## 5. Changes made (same commit as this document)

| File | Change |
|---|---|
| `soroban-env-host/benches/common/cost_types/num_ops.rs` | New `Int256Mul` and `Int256Pow` worst-case inputs with corrected comments. |
| `soroban-env-host/src/budget.rs` | 15 CPU `const_term`/`lin_term` values updated verbatim (table above). |
| `soroban-env-host/src/test/num.rs` | Pow calibration test comment corrected; two assertions added pinning that bases −2 and 3 overflow at exponents 256 and 162. |
| `soroban-env-host/tests/ed25519_edge_cases.rs` | The ZIP-215 test verifies 196 signatures on one host; at the new per-verify cost it exhausted the default 100M budget at vector 132. Now resets the budget per vector, mirroring `secp256r1_sig_ver.rs`. |
| `soroban-env-host/src/test/{budget_metering,auth,stellar_asset_contract}.rs` | `expect!` snapshots re-recorded (`UPDATE_EXPECT=1`); the random-inputs snapshot total moved 73,154,482 → 72,260,581. |
| `soroban-env-host/observations/*.json` (76 files) | Re-recorded with `UPDATE_OBSERVATIONS=1 --features testutils`. |

Verification: `cargo test --locked --workspace --profile test-opt` all green
(857 host lib tests + integration tests); `cargo fmt --all` clean. `cargo clippy
--all-targets --features bench,testutils` on stable 1.90 reports pre-existing lints
only in files not touched here.

## 6. Limitations (left uncorrected, per the no-padding rule)

1. **Projective-to-affine worst `Z`** is not constructed; the committed value is the
   max over 10,000 random `Z`. A deliberately adversarial `Z` for binary-Euclid
   inversion could exceed it by a few percent.
2. **`Int256Mul`/`Int256Pow` include separately-metered work** in the measured region:
   `Int256Mul`'s worst case necessarily produces an object result (the alloc is also
   charged under `MemAlloc`), and both include two `VisitObject`s where inputs are
   objects. The harness cannot subtract nested charges; this is shared with every
   other host-function constant model.
3. **Int256Mul Knuth path corner**: a divisor/dividend pair that takes both q-hat
   corrections plus the D6 add-back would be a handful of instructions higher;
   probability ≈ 2⁻¹²⁷ for the fixed dividend, not pursued.
4. **No-AVX2 vs production**: validators that *do* have AVX2 will run ~1.8× fewer
   instructions for Ed25519 than charged. This is the intended conservative choice
   (covers non-AVX2 hardware, portable across machines), not a measurement error.
5. **Overflow checks**: kept at the repo default (on). Earlier in this session,
   disabling them lowered `RecoverEcdsaSecp256k1Key` by 5.6%, `DecodeEcdsaCurve256Sig`
   by 17% and Ed25519 (no-AVX2) by 8.6%; whether stellar-core's release build keeps
   them on was not verified.
6. `Ed25519ScalarMul`, `EcdsaSecp256r1Recover`, `Sec1DecodePointCompressed`,
   `DecodeSecp256r1Sig` are experimental cost types not in `budget.rs` and were not
   measured.
