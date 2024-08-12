use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::{MillerLoopOutput, PairingOutput};

use crate::{
    budget::CostTracker, cost_runner::{CostRunner, CostType}, VecObject
};
use std::hint::black_box;
use super::ExperimentalCostType::*;

pub struct Bls12381G1AddRun;
pub struct Bls12381G1MulRun;
pub struct Bls12381G1MsmRun;
pub struct Bls12381MapFpToG1Run;
pub struct Bls12381HashToG1Run;
pub struct Bls12381G2AddRun;
pub struct Bls12381G2MsmRun;
pub struct Bls12381G2MulRun;
pub struct Bls12381MapFp2ToG2Run;
pub struct Bls12381HashToG2Run;
pub struct Bls12381MillerLoopRun;
pub struct Bls12381FinalExpRun;
pub struct Bls12381PairingRun;

#[derive(Clone)]
pub struct Bls12381G1AddSample(pub G1Affine, pub G1Affine);
#[derive(Clone)]
pub struct Bls12381G1MulSample(pub G1Affine, pub Fr);
#[derive(Clone)]
pub struct Bls12381G1MsmSample(pub VecObject, pub VecObject);
#[derive(Clone)]
pub struct Bls12381MapFpToG1Sample(pub Fq);
#[derive(Clone)]
pub struct Bls12381HashToG1Sample(pub Vec<u8>);
#[derive(Clone)]
pub struct Bls12381G2AddSample(pub G2Affine, pub G2Affine);
#[derive(Clone)]
pub struct Bls12381G2MulSample(pub G2Affine, pub Fr);
#[derive(Clone)]
pub struct Bls12381G2MsmSample(pub VecObject, pub VecObject);
#[derive(Clone)]
pub struct Bls12381MapFp2ToG2Sample(pub Fq2);
#[derive(Clone)]
pub struct Bls12381HashToG2Sample(pub Vec<u8>);
#[derive(Clone)]
pub struct Bls12381MillerLoopSample(pub G1Affine, pub G2Affine);
#[derive(Clone)]
pub struct Bls12381FinalExpSample(pub MillerLoopOutput<Bls12_381>);
#[derive(Clone)]
pub struct Bls12381PairingSample(pub G1Affine, pub G2Affine);

macro_rules! impl_runner_for_bls {
    ($runner: ident, $cost: ident, $host_fn: ident, $sample: ident, $rt: ty, $($arg: ident),*) => {
        impl CostRunner for $runner {
            const COST_TYPE: CostType = CostType::Experimental($cost);
        
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
            
            fn get_tracker(_host: &crate::Host) -> CostTracker {
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

impl_runner_for_bls!(Bls12381G1AddRun, Bls12381G1Add, g1_add_internal, Bls12381G1AddSample, G1Projective, p0, p1);
impl_runner_for_bls!(Bls12381G1MulRun, Bls12381G1Mul, g1_mul_internal, Bls12381G1MulSample, G1Projective, p0, scalar);
impl_runner_for_bls!(Bls12381G1MsmRun, Bls12381G1Msm, g1_msm_from_vecobj, Bls12381G1MsmSample, G1Projective, vp, vs);
impl_runner_for_bls!(Bls12381MapFpToG1Run, Bls12381MapFpToG1, map_fp_to_g1_internal, Bls12381MapFpToG1Sample, G1Affine, fq);
impl_runner_for_bls!(Bls12381HashToG1Run, Bls12381HashToG1, hash_to_g1_internal, Bls12381HashToG1Sample, G1Affine, msg);
impl_runner_for_bls!(Bls12381G2AddRun, Bls12381G2Add, g2_add_internal, Bls12381G2AddSample, G2Projective, p0, p1);
impl_runner_for_bls!(Bls12381G2MulRun, Bls12381G2Mul, g2_mul_internal, Bls12381G2MulSample, G2Projective, p0, scalar);
impl_runner_for_bls!(Bls12381G2MsmRun, Bls12381G2Msm, g2_msm_from_vecobj, Bls12381G2MsmSample, G2Projective, vp, vs);
impl_runner_for_bls!(Bls12381MapFp2ToG2Run, Bls12381MapFp2ToG2, map_fp2_to_g2_internal, Bls12381MapFp2ToG2Sample, G2Affine, fq2);
impl_runner_for_bls!(Bls12381HashToG2Run, Bls12381HashToG2, hash_to_g2_internal, Bls12381HashToG2Sample, G2Affine, msg);
impl_runner_for_bls!(Bls12381PairingRun, Bls12381Pairing, pairing_internal, Bls12381PairingSample, PairingOutput<Bls12_381>, p0, p1);