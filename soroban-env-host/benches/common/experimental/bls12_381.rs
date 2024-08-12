use crate::common::HostCostMeasurement;
use ark_bls12_381::G1Affine;
use ark_ff::UniformRand;
use rand::rngs::StdRng;
use soroban_env_host::{
    cost_runner::{Bls12381G1AddSample, Bls12381G1AddRun},
    Host,
};

pub(crate) struct Bls12381G1AddMeasure {}

impl HostCostMeasurement for Bls12381G1AddMeasure {
    type Runner = Bls12381G1AddRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381G1AddSample {
        let p0 = G1Affine::rand(rng);
        let p1 = G1Affine::rand(rng);
        Bls12381G1AddSample{ p0, p1 }
    }
}
