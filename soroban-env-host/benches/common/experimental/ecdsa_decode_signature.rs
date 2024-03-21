use crate::common::HostCostMeasurement;
use ecdsa::signature::hazmat::PrehashSigner;
use elliptic_curve::scalar::IsHigh;
use rand::{rngs::StdRng, RngCore};
use soroban_env_host::{
    cost_runner::{
        DecodeSecp256k1SignatureRun, DecodeSecp256r1SignatureRun, EcdsaDecodeSignatureSample,
    },
    xdr::Hash,
    Host,
};

pub(crate) struct DecodeSecp256r1SignatureMeasure {}

impl HostCostMeasurement for DecodeSecp256r1SignatureMeasure {
    type Runner = DecodeSecp256r1SignatureRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> EcdsaDecodeSignatureSample {
        use p256::ecdsa::{Signature, SigningKey};

        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let signer = SigningKey::from_bytes(&key_bytes.into()).unwrap();
        let mut msg_hash = [0u8; 32];
        rng.fill_bytes(&mut msg_hash);
        let mut sig: Signature = signer.sign_prehash(&msg_hash).unwrap();
        // in our host implementation, we are rejecting high `s`, we are doing it here too.
        if bool::from(sig.s().is_high()) {
            sig = sig.normalize_s().unwrap();
        }
        EcdsaDecodeSignatureSample {
            bytes: sig.to_vec(),
        }
    }
}
pub(crate) struct DecodeSecp256k1SignatureMeasure {}

impl HostCostMeasurement for DecodeSecp256k1SignatureMeasure {
    type Runner = DecodeSecp256k1SignatureRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> EcdsaDecodeSignatureSample {
        use k256::ecdsa::{Signature, SigningKey};

        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let signer = SigningKey::from_bytes(&key_bytes.into()).unwrap();
        let mut msg_hash = [0u8; 32];
        rng.fill_bytes(&mut msg_hash);
        let mut sig: Signature = signer.sign_prehash(&msg_hash).unwrap();
        // in our host implementation, we are rejecting high `s`, we are doing it here too.
        if bool::from(sig.s().is_high()) {
            sig = sig.normalize_s().unwrap();
        }
        EcdsaDecodeSignatureSample {
            bytes: sig.to_vec(),
        }
    }
}
