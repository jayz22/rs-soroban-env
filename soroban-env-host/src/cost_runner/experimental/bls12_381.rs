use ark_bls12_381::{G1Affine, G1Projective};

use crate::{
    budget::CostTracker, cost_runner::{CostRunner, CostType}
};
use std::hint::black_box;
use super::ExperimentalCostType::*;

pub struct Bls12381G1AddRun;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct Bls12381G1AddSample {
    pub p0: G1Affine,
    pub p1: G1Affine,
}

impl CostRunner for Bls12381G1AddRun {
    const COST_TYPE: CostType = CostType::Experimental(Bls12381G1Add);

    type SampleType = Bls12381G1AddSample;

    type RecycledType = (Option<Self::SampleType>, Option<G1Projective>);

    fn run_iter(host: &crate::Host, _iter: u64, sample: Self::SampleType) -> Self::RecycledType {
        let res = host.g1_add_internal(sample.p0, sample.p1).unwrap();
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
    
    fn get_tracker(_host: &crate::Host) -> CostTracker {
        CostTracker {
            iterations: Self::RUN_ITERATIONS,
            inputs: None,
            cpu: 0,
            mem: 0,
        }
    }
}
