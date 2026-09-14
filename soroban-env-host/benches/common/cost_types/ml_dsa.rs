use crate::common::HostCostMeasurement;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams, SigningKey};
use rand::{rngs::StdRng, RngCore};
use soroban_env_host::{
    cost_runner::{
        MlDsa44DecodeSignatureRun, MlDsa44DecodeVerifyingKeyRun, MlDsa65DecodeSignatureRun,
        MlDsa65DecodeVerifyingKeyRun, MlDsa87DecodeSignatureRun, MlDsa87DecodeVerifyingKeyRun,
        MlDsaDecodeSignatureSample, MlDsaDecodeVerifyingKeySample, MlDsaVerifySigSample,
        VerifyMlDsa44SigRun, VerifyMlDsa65SigRun, VerifyMlDsa87SigRun,
    },
    Host,
};

/// FIPS 204 caps the context string at 255 bytes, so it contributes a bounded
/// amount to the linear term. We use a mid-range fixed length so the fitted
/// model sees a non-empty context without letting it dominate the sweep.
const CTX_LEN: usize = 128;

fn random_signing_key<P: MlDsaParams>(rng: &mut StdRng) -> SigningKey<P> {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    SigningKey::<P>::from_seed(&seed.into())
}

fn decode_vk_sample<P: MlDsaParams>(rng: &mut StdRng) -> MlDsaDecodeVerifyingKeySample {
    let sk = random_signing_key::<P>(rng);
    let vk = sk.expanded_key().verifying_key();
    MlDsaDecodeVerifyingKeySample {
        bytes: vk.encode().to_vec(),
    }
}

fn decode_sig_sample<P: MlDsaParams>(rng: &mut StdRng) -> MlDsaDecodeSignatureSample {
    let sk = random_signing_key::<P>(rng);
    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);
    let sig = sk
        .expanded_key()
        .sign_deterministic(&msg, &[])
        .expect("deterministic signing");
    MlDsaDecodeSignatureSample {
        bytes: sig.encode().to_vec(),
    }
}

fn verify_sample<P: MlDsaParams>(rng: &mut StdRng, total_len: u64) -> MlDsaVerifySigSample<P> {
    let sk = random_signing_key::<P>(rng);
    let vk = sk.expanded_key().verifying_key();
    // The linear input is the combined message and context length, so the
    // context length is subtracted from the requested total.
    let msg_len = (total_len as usize).saturating_sub(CTX_LEN);
    let mut msg = vec![0u8; msg_len];
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
        $p:ty,
        $decode_vk_measure:ident, $decode_vk_run:ident,
        $decode_sig_measure:ident, $decode_sig_run:ident,
        $verify_measure:ident, $verify_run:ident
    ) => {
        // Constant-cost measurement: decoding (and expanding) a random
        // verifying key. Input is ignored.
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

        // Constant-cost measurement: unpacking and validating the hint and
        // response vectors of a random signature. Input is ignored.
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
        }

        // Linear measurement: verification of a random signature, with the
        // combined message and context length scaling with the input (the
        // SHAKE-256 absorption computing `mu` is the linear component).
        pub(crate) struct $verify_measure;

        impl HostCostMeasurement for $verify_measure {
            type Runner = $verify_run;

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
    MlDsa44DecodeVerifyingKeyMeasure,
    MlDsa44DecodeVerifyingKeyRun,
    MlDsa44DecodeSignatureMeasure,
    MlDsa44DecodeSignatureRun,
    VerifyMlDsa44SigMeasure,
    VerifyMlDsa44SigRun
);
impl_ml_dsa_measures!(
    MlDsa65,
    MlDsa65DecodeVerifyingKeyMeasure,
    MlDsa65DecodeVerifyingKeyRun,
    MlDsa65DecodeSignatureMeasure,
    MlDsa65DecodeSignatureRun,
    VerifyMlDsa65SigMeasure,
    VerifyMlDsa65SigRun
);
impl_ml_dsa_measures!(
    MlDsa87,
    MlDsa87DecodeVerifyingKeyMeasure,
    MlDsa87DecodeVerifyingKeyRun,
    MlDsa87DecodeSignatureMeasure,
    MlDsa87DecodeSignatureRun,
    VerifyMlDsa87SigMeasure,
    VerifyMlDsa87SigRun
);
