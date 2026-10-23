#!/bin/bash
# Full recalibration on the no-AVX2 build (serial curve25519-dalek backend,
# sha2 force-soft), overflow checks left at the repo default (on).
# Writes one log per cost type into docs/calibration-2026-10-logs/final/.
# Usage: run from the repository root.
set -u
ROOT=$(git rev-parse --show-toplevel) || exit 1
cd "$ROOT" || exit 1
S="$ROOT/docs/calibration-2026-10-logs/final"
mkdir -p "$S"
export CARGO_TARGET_DIR=target-serial
export RUSTFLAGS='-Dwarnings --cfg curve25519_dalek_backend="serial"'
FEAT=bench,sha2/force-soft

cargo bench -p soroban-env-host --features $FEAT --bench variation_histograms --no-run > "$S/build_hist.log" 2>&1 || { echo "hist build failed"; exit 1; }
cargo bench -p soroban-env-host --features $FEAT --bench worst_case_linear_models --no-run > "$S/build_linear.log" 2>&1 || { echo "linear build failed"; exit 1; }

CONST="Int256Mul Int256Pow Bls12381G1Mul Bls12381G2Mul Bn254G1Mul Bn254G1ProjectiveToAffine Bls12381G1ProjectiveToAffine ComputeEd25519PubKey RecoverEcdsaSecp256k1Key VerifyEcdsaSecp256r1Sig"
for ct in $CONST; do
  RUN_ITERATIONS=1 SAMPLE_COUNT=10000 CHECK_RANGE_AGAINST_BASELINE=1 \
    cargo bench -p soroban-env-host --features $FEAT --bench variation_histograms -- "$ct" > "$S/hist_$ct.log" 2>&1
  echo "$ct exit $?"
done
# Without the range check: Int256Shift, DecodeEcdsaCurve256Sig and
# Sec1DecodePointUncompressed are too cheap to clear the 10x-baseline check at
# RUN_ITERATIONS=1; Bls12381G2ProjectiveToAffine trips its wall-time variant.
for ct in Int256Shift Bls12381G2ProjectiveToAffine DecodeEcdsaCurve256Sig Sec1DecodePointUncompressed; do
  RUN_ITERATIONS=1 SAMPLE_COUNT=10000 \
    cargo bench -p soroban-env-host --features $FEAT --bench variation_histograms -- "$ct" > "$S/hist_$ct.log" 2>&1
  echo "$ct exit $?"
done
CHECK_RANGE_AGAINST_BASELINE=1 WRITE_PARAMS=1 SKIP_WASM_INSNS=1 \
  cargo bench -p soroban-env-host --features $FEAT --bench worst_case_linear_models -- VerifyEd25519Sig > "$S/linear_VerifyEd25519Sig.log" 2>&1
echo "VerifyEd25519Sig exit $?"
echo ALL DONE
