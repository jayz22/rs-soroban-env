use crate::{
    budget::CostTracker,
    cost_runner::{CostRunner, CostType},
    xdr::Hash,
};
use ecdsa::RecoveryId;
use k256::Secp256k1;
use p256::{ecdsa::VerifyingKey, NistP256};
use std::hint::black_box;

use super::ExperimentalCostType;

pub struct DecodeSecp256r1SignatureRun;
pub struct DecodeSecp256k1SignatureRun;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct EcdsaDecodeSignatureSample {
    pub bytes: Vec<u8>,
}

impl CostRunner for DecodeSecp256r1SignatureRun {
    const COST_TYPE: CostType =
        CostType::Experimental(ExperimentalCostType::DecodeSecp256r1Signature);

    const RUN_ITERATIONS: u64 = 100;

    type SampleType = EcdsaDecodeSignatureSample;

    type RecycledType = (Self::SampleType, Option<p256::ecdsa::Signature>);

    fn run_iter(host: &crate::Host, _iter: u64, sample: Self::SampleType) -> Self::RecycledType {
        let sig = host
            .ecdsa_signature_from_bytes::<NistP256>(&sample.bytes)
            .unwrap();
        black_box((sample, Some(sig)))
    }

    fn get_tracker(_host: &crate::Host) -> CostTracker {
        CostTracker {
            iterations: Self::RUN_ITERATIONS,
            inputs: None,
            cpu: 0,
            mem: 0,
        }
    }

    fn run_baseline_iter(
        _host: &crate::Host,
        _iter: u64,
        sample: Self::SampleType,
    ) -> Self::RecycledType {
        black_box((sample, None))
    }
}

impl CostRunner for DecodeSecp256k1SignatureRun {
    const COST_TYPE: CostType =
        CostType::Experimental(ExperimentalCostType::DecodeSecp256k1Signature);

    const RUN_ITERATIONS: u64 = 100;

    type SampleType = EcdsaDecodeSignatureSample;

    type RecycledType = (Self::SampleType, Option<k256::ecdsa::Signature>);

    fn run_iter(host: &crate::Host, _iter: u64, sample: Self::SampleType) -> Self::RecycledType {
        let sig = host
            .ecdsa_signature_from_bytes::<Secp256k1>(&sample.bytes)
            .unwrap();
        black_box((sample, Some(sig)))
    }

    fn get_tracker(_host: &crate::Host) -> CostTracker {
        CostTracker {
            iterations: Self::RUN_ITERATIONS,
            inputs: None,
            cpu: 0,
            mem: 0,
        }
    }

    fn run_baseline_iter(
        _host: &crate::Host,
        _iter: u64,
        sample: Self::SampleType,
    ) -> Self::RecycledType {
        black_box((sample, None))
    }
}
