use ark_bls12_381::{Bls12_381, Fq, Fq12, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::{MillerLoopOutput, PairingOutput};

use super::ExperimentalCostType::*;
use crate::{
    budget::CostTracker,
    cost_runner::{CostRunner, CostType},
};
use std::hint::black_box;

pub struct Bls12381G1ProjectiveToAffineRun;
pub struct Bls12381G1AddRun;
pub struct Bls12381G1MulRun;
pub struct Bls12381G1MsmRun;
pub struct Bls12381MapFpToG1Run;
pub struct Bls12381HashToG1Run;
pub struct Bls12381G2ProjectiveToAffineRun;
pub struct Bls12381G2AddRun;
pub struct Bls12381G2MsmRun;
pub struct Bls12381G2MulRun;
pub struct Bls12381MapFp2ToG2Run;
pub struct Bls12381HashToG2Run;
pub struct Bls12381MillerLoopRun;
pub struct Bls12381FinalExpRun;
pub struct Bls12381PairingRun;
pub struct Bls12381G1AffineSerializeUncompressedRun;
pub struct Bls12381G2AffineSerializeUncompressedRun;
pub struct Bls12381Fp12SerializeUncompressedRun;
pub struct Bls12381FpSerializeUncompressedRun;
pub struct Bls12381G1AffineDeserializeUncompressedRun;
pub struct Bls12381G2AffineDeserializeUncompressedRun;
pub struct Bls12381FpDeserializeUncompressedRun;
pub struct Bls12381Fp2DeserializeUncompressedRun;

#[derive(Clone)]
pub struct Bls12381G1ProjectiveToAffineSample(pub G1Projective);
#[derive(Clone)]
pub struct Bls12381G1AddSample(pub G1Affine, pub G1Affine);
#[derive(Clone)]
pub struct Bls12381G1MulSample(pub G1Affine, pub Fr);
#[derive(Clone)]
pub struct Bls12381G1MsmSample(pub Vec<G1Affine>, pub Vec<Fr>);
#[derive(Clone)]
pub struct Bls12381MapFpToG1Sample(pub Fq);
#[derive(Clone)]
pub struct Bls12381HashToG1Sample(pub Vec<u8>);
#[derive(Clone)]
pub struct Bls12381G2ProjectiveToAffineSample(pub G2Projective);
#[derive(Clone)]
pub struct Bls12381G2AddSample(pub G2Affine, pub G2Affine);
#[derive(Clone)]
pub struct Bls12381G2MulSample(pub G2Affine, pub Fr);
#[derive(Clone)]
pub struct Bls12381G2MsmSample(pub Vec<G2Affine>, pub Vec<Fr>);
#[derive(Clone)]
pub struct Bls12381MapFp2ToG2Sample(pub Fq2);
#[derive(Clone)]
pub struct Bls12381HashToG2Sample(pub Vec<u8>);
#[derive(Clone)]
pub struct Bls12381MillerLoopSample(pub G1Affine, pub G2Affine);
#[derive(Clone)]
pub struct Bls12381FinalExpSample(pub MillerLoopOutput<Bls12_381>);
#[derive(Clone)]
pub struct Bls12381PairingSample(pub Vec<G1Affine>, pub Vec<G2Affine>);

macro_rules! impl_const_cost_runner_for_bls {
    ($runner: ident, $cost: ident, $host_fn: ident, $sample: ident, $rt: ty, $($arg: ident),*) => {
        impl CostRunner for $runner {
            const COST_TYPE: CostType = CostType::Experimental($cost);

            const RUN_ITERATIONS: u64 = 1;

            type SampleType = $sample;

            type RecycledType = (Option<$sample>, Option<$rt>);

            fn run_iter(host: &crate::Host, _iter: u64, sample: $sample) -> Self::RecycledType {
                let $sample($( $arg ),*) = sample;
                let res = host.$host_fn($($arg),*).unwrap();
                black_box((None, Some(res)))
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

impl_const_cost_runner_for_bls!(
    Bls12381G1ProjectiveToAffineRun,
    Bls12381G1ProjectiveToAffine,
    g1_projective_into_affine,
    Bls12381G1ProjectiveToAffineSample,
    G1Affine,
    p0
);
impl_const_cost_runner_for_bls!(
    Bls12381G1AddRun,
    Bls12381G1Add,
    g1_add_internal,
    Bls12381G1AddSample,
    G1Projective,
    p0,
    p1
);
impl_const_cost_runner_for_bls!(
    Bls12381G1MulRun,
    Bls12381G1Mul,
    g1_mul_internal,
    Bls12381G1MulSample,
    G1Projective,
    p0,
    scalar
);
impl_const_cost_runner_for_bls!(
    Bls12381MapFpToG1Run,
    Bls12381MapFpToG1,
    map_fp_to_g1_internal,
    Bls12381MapFpToG1Sample,
    G1Affine,
    fq
);
impl_const_cost_runner_for_bls!(
    Bls12381HashToG1Run,
    Bls12381HashToG1,
    hash_to_g1_internal,
    Bls12381HashToG1Sample,
    G1Affine,
    msg
);
impl_const_cost_runner_for_bls!(
    Bls12381G2ProjectiveToAffineRun,
    Bls12381G2ProjectiveToAffine,
    g2_projective_into_affine,
    Bls12381G2ProjectiveToAffineSample,
    G2Affine,
    p0
);
impl_const_cost_runner_for_bls!(
    Bls12381G2AddRun,
    Bls12381G2Add,
    g2_add_internal,
    Bls12381G2AddSample,
    G2Projective,
    p0,
    p1
);
impl_const_cost_runner_for_bls!(
    Bls12381G2MulRun,
    Bls12381G2Mul,
    g2_mul_internal,
    Bls12381G2MulSample,
    G2Projective,
    p0,
    scalar
);
impl_const_cost_runner_for_bls!(
    Bls12381MapFp2ToG2Run,
    Bls12381MapFp2ToG2,
    map_fp2_to_g2_internal,
    Bls12381MapFp2ToG2Sample,
    G2Affine,
    fq2
);
impl_const_cost_runner_for_bls!(
    Bls12381HashToG2Run,
    Bls12381HashToG2,
    hash_to_g2_internal,
    Bls12381HashToG2Sample,
    G2Affine,
    msg
);

impl CostRunner for Bls12381G1MsmRun {
    const COST_TYPE: CostType = CostType::Experimental(Bls12381G1Msm);

    const RUN_ITERATIONS: u64 = 1;

    type SampleType = Bls12381G1MsmSample;

    type RecycledType = (Option<Self::SampleType>, Option<G1Projective>);

    fn run_iter(host: &crate::Host, _iter: u64, sample: Self::SampleType) -> Self::RecycledType {
        let res = host.g1_msm_internal(&sample.0, &sample.1).unwrap();
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

    fn get_tracker(_host: &crate::Host, sample: &Self::SampleType) -> CostTracker {
        CostTracker {
            iterations: Self::RUN_ITERATIONS,
            inputs: Some(sample.0.len() as u64),
            cpu: 0,
            mem: 0,
        }
    }
}

impl CostRunner for Bls12381G2MsmRun {
    const COST_TYPE: CostType = CostType::Experimental(Bls12381G2Msm);

    const RUN_ITERATIONS: u64 = 1;

    type SampleType = Bls12381G2MsmSample;

    type RecycledType = (Option<Self::SampleType>, Option<G2Projective>);

    fn run_iter(host: &crate::Host, _iter: u64, sample: Self::SampleType) -> Self::RecycledType {
        let res = host.g2_msm_internal(&sample.0, &sample.1).unwrap();
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

    fn get_tracker(_host: &crate::Host, sample: &Self::SampleType) -> CostTracker {
        CostTracker {
            iterations: Self::RUN_ITERATIONS,
            inputs: Some(sample.0.len() as u64),
            cpu: 0,
            mem: 0,
        }
    }
}

impl CostRunner for Bls12381PairingRun {
    const COST_TYPE: CostType = CostType::Experimental(Bls12381Pairing);

    const RUN_ITERATIONS: u64 = 1;

    type SampleType = Bls12381PairingSample;

    type RecycledType = (Option<Self::SampleType>, Option<PairingOutput<Bls12_381>>);

    fn run_iter(host: &crate::Host, _iter: u64, sample: Self::SampleType) -> Self::RecycledType {
        let res = host.pairing_internal(sample.0, sample.1).unwrap();
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

    fn get_tracker(_host: &crate::Host, sample: &Self::SampleType) -> CostTracker {
        CostTracker {
            iterations: Self::RUN_ITERATIONS,
            inputs: Some(sample.0.len() as u64),
            cpu: 0,
            mem: 0,
        }
    }
}

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
impl_ser_runner_for_bls!(
    Bls12381Fp12SerializeUncompressedRun,
    Bls12381Fp12SerializeUncompressed,
    Fq12
);
impl_ser_runner_for_bls!(
    Bls12381FpSerializeUncompressedRun,
    Bls12381FpSerializeUncompressed,
    Fq
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
    Bls12381FpDeserializeUncompressedRun,
    Bls12381FpDeserializeUncompressed,
    Fq
);
impl_deser_runner_for_bls!(
    Bls12381Fp2DeserializeUncompressedRun,
    Bls12381Fp2DeserializeUncompressed,
    Fq2
);
