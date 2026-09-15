use crate::common::HostCostMeasurement;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams, SigningKey};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use soroban_env_host::{
    cost_runner::{
        MlDsa44DecodeSignatureRun, MlDsa44DecodeVerifyingKeyRun, MlDsa65DecodeSignatureRun,
        MlDsa65DecodeVerifyingKeyRun, MlDsa87DecodeSignatureRun, MlDsa87DecodeVerifyingKeyRun,
        MlDsaDecodeSignatureSample, MlDsaDecodeVerifyingKeySample, MlDsaVerifySigSample,
        VerifyMlDsa44SigRun, VerifyMlDsa65SigRun, VerifyMlDsa87SigRun,
    },
    Host,
};
use std::sync::OnceLock;

/// The context string is fixed at zero length for calibration.
///
/// The charged input is `msg.len() + ctx.len()`, and the SHAKE-256 absorption
/// that computes `mu` takes `tr || 0x00 || len(ctx) || ctx || M`. The absorbed
/// length is therefore `66 + (msg + ctx)` however the total is split, so
/// context and message bytes are interchangeable byte-for-byte in the cost
/// model. Fixing it at 0 matches the common case (no domain separator).
const CTX_LEN: usize = 0;

/// SHAKE-256 rate in bytes: (1600 - 512) / 8.
///
/// The linear component of verification is the SHAKE-256 absorption computing
/// `mu`, which costs one Keccak-f[1600] permutation per 136-byte block.
const SHAKE256_RATE: u64 = 136;

/// Deterministic seed for the worst-case search
const WORST_CASE_SEED: [u8; 32] = [0xa5; 32];

/// Attempts allowed when searching for a maximum-hint-weight signature.
/// Honest signing reaches omega in roughly 0.1-0.7% of signatures depending on
/// the variant, so this is far above the expected requirement.
const WORST_CASE_MAX_ATTEMPTS: usize = 50_000;

fn random_signing_key<P: MlDsaParams>(rng: &mut StdRng) -> SigningKey<P> {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    SigningKey::<P>::from_seed(&seed.into())
}

fn sign_random<P: MlDsaParams>(rng: &mut StdRng) -> Vec<u8> {
    let sk = random_signing_key::<P>(rng);
    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);
    sk.expanded_key()
        .sign_deterministic(&msg, &[])
        .expect("deterministic signing")
        .encode()
        .to_vec()
}

/// Total hint weight of an encoded ML-DSA signature.
///
/// The encoding is `c_tilde || z || hint`, where the hint is `omega` index
/// bytes followed by `k` cumulative cut bytes. The final byte is therefore the
/// cumulative total, i.e. the number of set hint bits.
fn hint_weight(sig: &[u8]) -> usize {
    *sig.last().expect("non-empty signature") as usize
}

/// Searches for an honest signature at the maximum hint weight `omega`.
///
/// Only data-dependent work
/// is `Hint::bit_unpack`, whose cost was measured to increase monotonically
/// with hint weight. The worst case is
/// therefore a well-formed signature at weight `omega`, which honest signing
/// does produce -- the signer rejects anything above `omega`, making it the
/// attainable ceiling.
fn max_hint_weight_signature<P: MlDsaParams>(omega: usize) -> Vec<u8> {
    let mut rng = StdRng::from_seed(WORST_CASE_SEED);
    let mut best: Option<Vec<u8>> = None;
    for _ in 0..WORST_CASE_MAX_ATTEMPTS {
        let sig = sign_random::<P>(&mut rng);
        if best
            .as_ref()
            .map_or(true, |b| hint_weight(&sig) > hint_weight(b))
        {
            best = Some(sig);
        }
        if best.as_ref().map_or(false, |b| hint_weight(b) == omega) {
            break;
        }
    }
    best.expect("at least one signature")
}

fn decode_vk_sample<P: MlDsaParams>(rng: &mut StdRng) -> MlDsaDecodeVerifyingKeySample {
    let sk = random_signing_key::<P>(rng);
    let vk = sk.expanded_key().verifying_key();
    MlDsaDecodeVerifyingKeySample {
        bytes: vk.encode().to_vec(),
    }
}

fn decode_sig_sample<P: MlDsaParams>(rng: &mut StdRng) -> MlDsaDecodeSignatureSample {
    MlDsaDecodeSignatureSample {
        bytes: sign_random::<P>(rng),
    }
}

fn verify_sample<P: MlDsaParams>(rng: &mut StdRng, total_len: u64) -> MlDsaVerifySigSample<P> {
    let sk = random_signing_key::<P>(rng);
    let vk = sk.expanded_key().verifying_key();
    // The charged input is the combined message and context length; with the
    // context fixed at zero the swept total is entirely message.
    let mut msg = vec![0u8; total_len as usize - CTX_LEN];
    rng.fill_bytes(&mut msg);
    let mut ctx = vec![0u8; CTX_LEN];
    rng.fill_bytes(&mut ctx);
    let sig = sk
        .expanded_key()
        .sign_deterministic(&msg, &ctx)
        .expect("deterministic signing");
    MlDsaVerifySigSample { vk, msg, sig, ctx }
}

macro_rules! impl_ml_dsa_measures {
    (
        $p:ty, $omega:expr, $worst_sig:ident,
        $decode_vk_measure:ident, $decode_vk_run:ident,
        $decode_sig_measure:ident, $decode_sig_run:ident,
        $verify_measure:ident, $verify_run:ident
    ) => {
        // Constant-cost measurement: decoding (and expanding) a random
        // verifying key. Input is ignored.
        //
        // `new_worst_case` is deliberately left as the default (random). The
        // only data-dependent work is rejection sampling inside the SHAKE-128
        // `A_hat` expansion, which averages over `k*l*256` coefficients and so
        // concentrates tightly (measured max/min = 1.0006). There is no
        // constructible worst case short of searching over `rho`.
        pub(crate) struct $decode_vk_measure;

        impl HostCostMeasurement for $decode_vk_measure {
            type Runner = $decode_vk_run;

            fn new_random_case(
                _host: &Host,
                rng: &mut StdRng,
                _input: u64,
            ) -> MlDsaDecodeVerifyingKeySample {
                decode_vk_sample::<$p>(rng)
            }
        }

        static $worst_sig: OnceLock<Vec<u8>> = OnceLock::new();

        // Constant-cost measurement: unpacking and validating the hint and
        // response vectors of a signature. Input is ignored.
        pub(crate) struct $decode_sig_measure;

        impl HostCostMeasurement for $decode_sig_measure {
            type Runner = $decode_sig_run;

            fn new_random_case(
                _host: &Host,
                rng: &mut StdRng,
                _input: u64,
            ) -> MlDsaDecodeSignatureSample {
                decode_sig_sample::<$p>(rng)
            }

            // Decode cost increases monotonically with hint weight, so the
            // worst case is a signature at the maximum weight `omega`. Cached,
            // since the linear bench calls this once per sweep point.
            fn new_worst_case(
                _host: &Host,
                _rng: &mut StdRng,
                _input: u64,
            ) -> MlDsaDecodeSignatureSample {
                MlDsaDecodeSignatureSample {
                    bytes: $worst_sig
                        .get_or_init(|| max_hint_weight_signature::<$p>($omega))
                        .clone(),
                }
            }
        }

        // Linear measurement: verification of a random signature, with the
        // message length scaling with the input (the SHAKE-256 absorption
        // computing `mu` is the linear component).
        pub(crate) struct $verify_measure;

        impl HostCostMeasurement for $verify_measure {
            type Runner = $verify_run;

            // Anchor the sweep at an empty message. The charged input is then
            // exactly 0, so the fitted constant term is a directly measured
            // quantity rather than an extrapolation (the fitter pins the line
            // through the first sample). This is not a degenerate sample:
            // SHAKE still absorbs 66 bytes of `tr || 0x00 || 0x00` and runs a
            // full permutation, and the entire lattice verification proceeds.
            const INPUT_BASE_SIZE: u64 = 0;
            const STEP_SIZE: u64 = SHAKE256_RATE;

            fn new_random_case(
                _host: &Host,
                rng: &mut StdRng,
                input: u64,
            ) -> MlDsaVerifySigSample<$p> {
                let size = Self::INPUT_BASE_SIZE + input * Self::STEP_SIZE;
                verify_sample::<$p>(rng, size)
            }
        }
    };
}

impl_ml_dsa_measures!(
    MlDsa44,
    80,
    ML_DSA_44_WORST_SIG,
    MlDsa44DecodeVerifyingKeyMeasure,
    MlDsa44DecodeVerifyingKeyRun,
    MlDsa44DecodeSignatureMeasure,
    MlDsa44DecodeSignatureRun,
    VerifyMlDsa44SigMeasure,
    VerifyMlDsa44SigRun
);
impl_ml_dsa_measures!(
    MlDsa65,
    55,
    ML_DSA_65_WORST_SIG,
    MlDsa65DecodeVerifyingKeyMeasure,
    MlDsa65DecodeVerifyingKeyRun,
    MlDsa65DecodeSignatureMeasure,
    MlDsa65DecodeSignatureRun,
    VerifyMlDsa65SigMeasure,
    VerifyMlDsa65SigRun
);
impl_ml_dsa_measures!(
    MlDsa87,
    75,
    ML_DSA_87_WORST_SIG,
    MlDsa87DecodeVerifyingKeyMeasure,
    MlDsa87DecodeVerifyingKeyRun,
    MlDsa87DecodeSignatureMeasure,
    MlDsa87DecodeSignatureRun,
    VerifyMlDsa87SigMeasure,
    VerifyMlDsa87SigRun
);
