use ark_bls12_381::{Bls12_381, Fq2,  G1Affine,  G2Affine, };
use ark_ec::pairing::MillerLoopOutput;

use super::ExperimentalCostType::*;
use crate::{
    budget::CostTracker,
    cost_runner::{CostRunner, CostType},
};
use std::hint::black_box;

pub struct Bls12381MillerLoopRun;
pub struct Bls12381FinalExpRun;
pub struct Bls12381G1AffineSerializeUncompressedRun;
pub struct Bls12381G2AffineSerializeUncompressedRun;
pub struct Bls12381G1AffineDeserializeUncompressedRun;
pub struct Bls12381G2AffineDeserializeUncompressedRun;
pub struct Bls12381Fp2DeserializeUncompressedRun;

#[derive(Clone)]
pub struct Bls12381MillerLoopSample(pub G1Affine, pub G2Affine);
#[derive(Clone)]
pub struct Bls12381FinalExpSample(pub MillerLoopOutput<Bls12_381>);

// ser/deser

macro_rules! impl_ser_runner_for_bls {
    ($runner: ident, $cost: ident, $sample: ident) => {
        impl CostRunner for $runner {
            const COST_TYPE: CostType = CostType::Experimental($cost);

            const RUN_ITERATIONS: u64 = 1;

            type SampleType = $sample;

            type RecycledType = (Option<$sample>, Option<Vec<u8>>);

            fn run_iter(host: &crate::Host, _iter: u64, sample: $sample) -> Self::RecycledType {
                let mut buf = vec![0u8; 1000];
                let _ = host
                    .serialize_into_bytesobj(
                        sample,
                        &mut buf,
                        crate::xdr::ContractCostType::Sec1DecodePointUncompressed,
                        "test",
                    )
                    .unwrap();
                black_box((None, Some(buf)))
            }

            fn run_baseline_iter(
                host: &crate::Host,
                _iter: u64,
                sample: $sample,
            ) -> Self::RecycledType {
                black_box(
                    host.charge_budget(crate::xdr::ContractCostType::Int256AddSub, None)
                        .unwrap(),
                );
                black_box((Some(sample), None))
            }

            fn get_tracker(_host: &crate::Host, _sample: &$sample) -> CostTracker {
                CostTracker {
                    iterations: Self::RUN_ITERATIONS,
                    inputs: None,
                    cpu: 0,
                    mem: 0,
                }
            }
        }
    };
}

impl_ser_runner_for_bls!(
    Bls12381G1AffineSerializeUncompressedRun,
    Bls12381G1AffineSerializeUncompressed,
    G1Affine
);
impl_ser_runner_for_bls!(
    Bls12381G2AffineSerializeUncompressedRun,
    Bls12381G2AffineSerializeUncompressed,
    G2Affine
);

macro_rules! impl_deser_runner_for_bls {
    ($runner: ident, $cost: ident, $rt: ty) => {
        impl CostRunner for $runner {
            const COST_TYPE: CostType = CostType::Experimental($cost);

            const RUN_ITERATIONS: u64 = 1;

            type SampleType = Vec<u8>;

            type RecycledType = (Option<Self::SampleType>, Option<$rt>);

            fn run_iter(
                host: &crate::Host,
                _iter: u64,
                sample: Self::SampleType,
            ) -> Self::RecycledType {
                let res = host
                    .deserialize_from_slice(
                        &sample,
                        crate::xdr::ContractCostType::Sec1DecodePointUncompressed,
                    )
                    .unwrap();
                black_box((None, Some(res)))
            }

            fn run_baseline_iter(
                host: &crate::Host,
                _iter: u64,
                sample: Self::SampleType,
            ) -> Self::RecycledType {
                black_box(
                    host.charge_budget(crate::xdr::ContractCostType::Int256AddSub, None)
                        .unwrap(),
                );
                black_box((Some(sample), None))
            }

            fn get_tracker(_host: &crate::Host, _sample: &Self::SampleType) -> CostTracker {
                CostTracker {
                    iterations: Self::RUN_ITERATIONS,
                    inputs: None,
                    cpu: 0,
                    mem: 0,
                }
            }
        }
    };
}

impl_deser_runner_for_bls!(
    Bls12381G1AffineDeserializeUncompressedRun,
    Bls12381G1AffineDeserializeUncompressed,
    G1Affine
);
impl_deser_runner_for_bls!(
    Bls12381G2AffineDeserializeUncompressedRun,
    Bls12381G2AffineDeserializeUncompressed,
    G2Affine
);
impl_deser_runner_for_bls!(
    Bls12381Fp2DeserializeUncompressedRun,
    Bls12381Fp2DeserializeUncompressed,
    Fq2
);
