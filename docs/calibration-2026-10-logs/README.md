# Raw data for `docs/calibration-2026-10-worst-case-no-avx2.md`

The original benchmark log files were lost to a `/tmp` wipe before they were
committed. What follows is the numeric content of those logs as it was captured
at the time (verbatim figures; the ASCII histogram plots and the full per-sample
lists are not recoverable). `scripts/calibrate.sh` reproduces the final
calibration into `final/`; both benches seed their RNG with a fixed value and
measure instruction counts, so a rerun yields the same numbers to within
measurement noise (repeat runs in the original session agreed within 0.02%).

All runs: Intel i7-10750H, Linux 6.2.0-39, rustc 1.90.0, `perf_event_paranoid=-1`,
overflow checks on unless stated. "no-AVX2" = `CARGO_TARGET_DIR=target-serial
RUSTFLAGS='-Dwarnings --cfg curve25519_dalek_backend="serial"'
--features bench,sha2/force-soft`.

## 1. Final calibration (no-AVX2 build; values committed to `budget.rs`)

`variation_histograms`, `RUN_ITERATIONS=1`, `SAMPLE_COUNT=10000`. Memory output
was constant for every type (80 B for `RecoverEcdsaSecp256k1Key`, else 0).

| Cost type | min | max | max/min | mean | std |
|---|---:|---:|---:|---:|---:|
| Int256Mul | 4,537 | 5,771 | 1.2719859 | 4,544.157 | 14.126811 |
| Int256Pow | 2,758 | 10,293 | 3.7320523 | 2,836.5686 | 107.54545 |
| Int256Shift | 2,047 | 2,100 | 1.0258915 | 2,070.9946 | 11.095935 |
| Bls12381G1Mul | 1,944,798 | 3,110,211 | 1.5992463 | 2,167,341 | 61,029.16 |
| Bls12381G2Mul | 6,050,753 | 9,836,091 | 1.6255978 | 6,729,283 | 199,703.97 |
| Bn254G1Mul | 923,157 | 1,467,330 | 1.5894697 | 1,024,557.56 | 28,535.648 |
| Bn254G1ProjectiveToAffine | 28,780 | 34,237 | 1.1896108 | 31,882.115 | 655.2672 |
| Bls12381G1ProjectiveToAffine | 77,016 | 87,728 | 1.139088 | 82,803.27 | 1,376.2838 |
| Bls12381G2ProjectiveToAffine | 85,681 | 95,662 | 1.1164902 | 91,190.5 | 1,382.181 |
| ComputeEd25519PubKey | 44,419 | 44,420 | 1.0000225 | 44,416.566 | 2.4344962 |
| RecoverEcdsaSecp256k1Key | 2,293,372 | 2,305,375 | 1.0052338 | 2,299,261 | 1,572.574 |
| VerifyEcdsaSecp256r1Sig | 2,902,877 | 2,915,981 | 1.0045141 | 2,909,826 | 1,611.2139 |
| DecodeEcdsaCurve256Sig | 824 | 824 | 1 | 824 | 0 |
| Sec1DecodePointUncompressed | 1,850 | 1,851 | 1.0005405 | 1,850.0002 | 0.01731699 |

Int256Mul memory: one 528-byte sample among 10,000, rest 0.

`worst_case_linear_models`, `RUN_ITERATIONS=100`, 20 points, `CHECK_RANGE_AGAINST_BASELINE=1`:

```
Contract(VerifyEd25519Sig) cpu: MeteredCostComponent { const_term: 706689, lin_term: ScaledU64(4229) }, R2 score: 0.9993221085575738
Contract(VerifyEd25519Sig) mem: MeteredCostComponent { const_term: 0, lin_term: ScaledU64(0) }, R2 score: NaN
```

Sweep table (`ave_net_input` bytes → `ave_net_insns`), no-AVX2 build:

| input | insns | input | insns |
|---:|---:|---:|---:|
| 1 | 706,722 | 10,241 | 1,045,183 |
| 1,025 | 742,892 | 11,265 | 1,068,081 |
| 2,049 | 776,688 | 12,289 | 1,114,847 |
| 3,073 | 806,283 | 13,313 | 1,147,311 |
| 4,097 | 835,683 | 14,337 | 1,184,678 |
| 5,121 | 873,505 | 15,361 | 1,222,196 |
| 6,145 | 906,936 | 16,385 | 1,243,302 |
| 7,169 | 952,336 | 17,409 | 1,279,932 |
| 8,193 | 981,255 | 18,433 | 1,322,849 |
| 9,217 | 1,010,989 | 19,457 | 1,340,938 |

Baseline (charge only) per point: 32,647 insns / 100 iterations.

## 2. Experiment: Ed25519 verify, AVX2 vs no-AVX2 build

Same sweep, default build (curve25519-dalek AVX2 backend + sha2 AVX2 SHA-512 active):

```
Contract(VerifyEd25519Sig) cpu: MeteredCostComponent { const_term: 393279, lin_term: ScaledU64(4383) }, R2 score: 0.9998597374492175
```

| input | insns | input | insns |
|---:|---:|---:|---:|
| 1 | 393,313 | 10,241 | 744,283 |
| 1,025 | 430,152 | 11,265 | 774,022 |
| 2,049 | 465,068 | 12,289 | 815,018 |
| 3,073 | 498,298 | 13,313 | 849,455 |
| 4,097 | 531,014 | 14,337 | 886,122 |
| 5,121 | 567,918 | 15,361 | 922,929 |
| 6,145 | 602,732 | 16,385 | 952,168 |
| 7,169 | 643,168 | 17,409 | 988,204 |
| 8,193 | 675,910 | 18,433 | 1,027,439 |
| 9,217 | 709,037 | 19,457 | 1,055,201 |

Wall time at 1 byte: 30.5 µs (AVX2) vs 48.2 µs (serial).

## 3. Experiment: overflow checks off (`CARGO_PROFILE_{BENCH,RELEASE}_OVERFLOW_CHECKS=false`)

| | checks on | checks off |
|---|---|---|
| VerifyEd25519Sig, AVX2 build | 393,279 / 4383, R² 0.99986 | 383,254 / 4320, R² 0.99985 |
| VerifyEd25519Sig, no-AVX2 build | 706,689 / 4229, R² 0.99932 | 646,105 / 4230, R² 0.99942 |
| RecoverEcdsaSecp256k1Key (max; min, mean, std) | 2,304,884 (2,293,233; 2,299,264.5; 1,591.6) | 2,176,260 (2,162,685; 2,170,053.8; 1,539.2) |
| VerifyEcdsaSecp256r1Sig | 2,915,981 (2,902,877; 2,909,825.8; 1,611.2) | 2,921,844 (2,908,907; 2,915,761.8; 1,593.8) |
| DecodeEcdsaCurve256Sig | 984 (983; 983.0; 0.01) | 819 (= min = max) |
| Sec1DecodePointUncompressed | 1,851 (1,850; 1,850.0; 0.014) | 1,846 (1,845; 1,844.9; 0.09) |

(secp types: default build, 10,000 samples, `RUN_ITERATIONS=1`.)

## 4. Worst-case searches (default build; `RUN_ITERATIONS=1`; "max" of a
3-sample run is the injected worst case when it exceeds the random samples)

### Int256Pow, exponent `u32::MAX`, 200 samples per base

| base | max | base | max |
|---:|---:|---:|---:|
| 1 | 10,293 | 4 | 7,826 |
| −1 | 10,293 | −4 | 7,915 |
| 0 | 10,293 | 5 | 7,189 |
| 2 | 8,228 | −5 | 7,273 |
| −2 | 9,012 | 7 | 7,163 |
| 3 | 8,226 | (random-only min) | 2,757 |
| −3 | 8,324 | | |

### Int256Mul (3 samples; random max ≈ 4,555)

Sweep 1, `a = 2^(253−k)+1`, `b = ±(2^(k−1)+1)`, non-overflowing ("ok") or overflowing ("ovf"):

| k (divisor bits) | ok same | ok opp | ovf same | ovf opp |
|---:|---:|---:|---:|---:|
| 2, 33 | 4,555 | 4,554 | 4,554 | 4,555 |
| 63 | 5,564 | 5,578 | 4,555 | 4,555 |
| 64 | 5,558 | 5,572 | 4,554 | 4,555 |
| 65 (committed in b9b5dc5b) | 5,604 | 5,664 | 4,555 | 4,554 |
| 66, 80 | 5,604 | 5,641 | 4,555 | 4,555 |
| 96, 127 | 5,604 | 5,618 | 4,555 | 4,554 |
| 128 | 5,504 | 5,534 | 4,554 | 4,554 |
| 129, 160 | 5,723 | 5,774 | 4,555 | 4,592 |
| 192 | 5,709 | 5,760 | 4,554 | 4,592 |

Sweep 3 (2-D, 229 pairs, divisor 65–253 bits × multiplicand width × pattern × sign):
maximum 5,774 for any divisor of 129–180 bits with the `2^(k−1)+1` pattern and
opposite signs, independent of multiplicand width or pattern; `2^k−1` and
`2^(k−1)+2^(k−2)` divisor patterns gave 5,738; same signs ≤ 5,723.
Chosen: `((1<<124)+1, −((1<<128)+1))`.

### Int256Shift (3 samples; random max 2,058)

| lhs | shift | max | note |
|---|---:|---:|---|
| MAX | 0 | 2,683 | result allocates |
| MAX | 1 (committed) | 2,106 | result −2, small |
| MAX | 63 | 2,705 | allocates |
| MAX | 64 / 65 / 127 | 2,719 | allocates |
| MAX | 128–255 | 2,696 | allocates |
| MAX | 256 / 300 / 2³²−1 | 2,059 / 2,081 / 2,058 | error path |
| MIN | 1 / 63 / 64 / 65 / 127 | 2,106 | small result |
| MIN | 128–255 | 2,083 | small result |
| 1 | any | ≤ 2,058 | small lhs |

### Scalar multiplication, worst (max-Hamming-weight scalar) vs random (3 samples)

| Cost type | random min | worst |
|---|---:|---:|
| Bn254G1Mul | 990,791 | 1,467,330 |
| Bls12381G1Mul | 2,216,981 | 3,110,212 |
| Bls12381G2Mul | 6,492,604 | 9,836,090 |
