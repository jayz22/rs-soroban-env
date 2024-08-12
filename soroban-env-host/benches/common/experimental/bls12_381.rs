use crate::common::HostCostMeasurement;
use ark_bls12_381::{Fq, Fr, G1Affine, G2Affine};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use rand::{rngs::StdRng, Rng};
use soroban_env_host::{
    cost_runner::{Bls12381G1AddRun, Bls12381G1AddSample, Bls12381G1MsmRun, Bls12381G1MsmSample, Bls12381G1MulRun, Bls12381G1MulSample, Bls12381MapFpToG1Run, Bls12381MapFpToG1Sample, Bls12381HashToG1Run, Bls12381HashToG1Sample, Bls12381PairingRun, Bls12381PairingSample
    }, Env, EnvBase, Host
};

pub(crate) struct Bls12381G1AddMeasure;

impl HostCostMeasurement for Bls12381G1AddMeasure {
    type Runner = Bls12381G1AddRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381G1AddSample {
        let p0 = G1Affine::rand(rng);
        let p1 = G1Affine::rand(rng);
        Bls12381G1AddSample(p0, p1)
    }
}

pub(crate) struct Bls12381G1MulMeasure;

impl HostCostMeasurement for Bls12381G1MulMeasure {
    type Runner = Bls12381G1MulRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381G1MulSample {
        let p0 = G1Affine::rand(rng);
        let p1 = Fr::rand(rng);
        Bls12381G1MulSample(p0, p1)
    }
}

pub(crate) struct Bls12381G1MsmMeasure;

impl HostCostMeasurement for Bls12381G1MsmMeasure {
    type Runner = Bls12381G1MsmRun;

    fn new_random_case(host: &Host, rng: &mut StdRng, input: u64) -> Bls12381G1MsmSample {
        let mut vp = host.vec_new().unwrap();
        let mut vs = host.vec_new().unwrap();
        for _i in 0..input {
            let mut p_buf = vec![0u8; 96];
            G1Affine::rand(rng).serialize_uncompressed(p_buf.as_mut_slice()).unwrap();
            let p_obj = host.bytes_new_from_slice(&p_buf).unwrap();
            vp = host.vec_push_back(vp, p_obj.to_val()).unwrap();

            let mut s_buf = vec![0u8; 32];
            Fr::rand(rng).serialize_uncompressed(s_buf.as_mut_slice()).unwrap();
            let s_obj = host.bytes_new_from_slice(&s_buf).unwrap();
            vs = host.vec_push_back(vs, s_obj.to_val()).unwrap();
        }
        Bls12381G1MsmSample(vp, vs)
    }
}

pub(crate) struct Bls12381MapFpToG1Measure;

impl HostCostMeasurement for Bls12381MapFpToG1Measure {
    type Runner = Bls12381MapFpToG1Run;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381MapFpToG1Sample {
        let fp = Fq::rand(rng);
        Bls12381MapFpToG1Sample(fp)
    }
}

pub(crate) struct Bls12381HashToG1Measure;

impl HostCostMeasurement for Bls12381HashToG1Measure {
    type Runner = Bls12381HashToG1Run;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381HashToG1Sample {
        let len = rng.gen_range(0..1000) as usize;
        let mut msg = vec![0u8; len];
        rng.fill(msg.as_mut_slice());
        Bls12381HashToG1Sample(msg)
    }
}

pub(crate) struct Bls12381PairingMeasure;

impl HostCostMeasurement for Bls12381PairingMeasure {
    type Runner = Bls12381PairingRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381PairingSample {
        let g1 = G1Affine::rand(rng);
        let g2 = G2Affine::rand(rng);
        Bls12381PairingSample(g1, g2)
    }
}
