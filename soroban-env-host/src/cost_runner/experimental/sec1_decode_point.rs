use crate::{
    budget::CostTracker,
    cost_runner::{CostRunner, CostType},
    xdr::Hash,
};
use ecdsa::RecoveryId;
use p256::ecdsa::{Signature, VerifyingKey};
use std::hint::black_box;

use super::ExperimentalCostType;

pub struct Sec1DecodePointCompressedRun;
pub struct Sec1DecodePointUncompressedRun;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct Sec1DecodePointSample {
    pub bytes: Box<[u8]>,
}

impl CostRunner for Sec1DecodePointCompressedRun {
    const COST_TYPE: CostType =
        CostType::Experimental(ExperimentalCostType::Sec1DecodePointCompressed);

    const RUN_ITERATIONS: u64 = 100;

    type SampleType = Sec1DecodePointSample;

    type RecycledType = (Self::SampleType, Option<VerifyingKey>);

    fn run_iter(_host: &crate::Host, _iter: u64, sample: Self::SampleType) -> Self::RecycledType {
        let vk = VerifyingKey::from_sec1_bytes(&sample.bytes).unwrap();
        black_box((sample, Some(vk)))
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

impl CostRunner for Sec1DecodePointUncompressedRun {
    const COST_TYPE: CostType =
        CostType::Experimental(ExperimentalCostType::Sec1DecodePointUncompressed);

    const RUN_ITERATIONS: u64 = 100;

    type SampleType = Sec1DecodePointSample;

    type RecycledType = (Self::SampleType, Option<VerifyingKey>);

    fn run_iter(_host: &crate::Host, _iter: u64, sample: Self::SampleType) -> Self::RecycledType {
        let vk = VerifyingKey::from_sec1_bytes(&sample.bytes).unwrap();
        black_box((sample, Some(vk)))
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
