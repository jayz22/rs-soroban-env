use crate::common::HostCostMeasurement;
use ark_bls12_381::{Fq, Fq12, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use rand::{rngs::StdRng, Rng};
use soroban_env_host::{
    cost_runner::{
        Bls12381Fp12SerializeUncompressedRun, Bls12381Fp2DeserializeUncompressedRun,
        Bls12381FpDeserializeUncompressedRun, Bls12381G1AddRun, Bls12381G1AddSample,
        Bls12381G1AffineDeserializeUncompressedRun, Bls12381G1AffineSerializeUncompressedRun,
        Bls12381G1MsmRun, Bls12381G1MsmSample, Bls12381G1MulRun, Bls12381G1MulSample,
        Bls12381G1ProjectiveToAffineRun, Bls12381G1ProjectiveToAffineSample, Bls12381G2AddRun,
        Bls12381G2AddSample, Bls12381G2AffineDeserializeUncompressedRun,
        Bls12381G2AffineSerializeUncompressedRun, Bls12381G2MsmRun, Bls12381G2MsmSample,
        Bls12381G2MulRun, Bls12381G2MulSample, Bls12381G2ProjectiveToAffineRun,
        Bls12381G2ProjectiveToAffineSample, Bls12381HashToG1Run, Bls12381HashToG1Sample,
        Bls12381HashToG2Run, Bls12381HashToG2Sample, Bls12381MapFp2ToG2Run,
        Bls12381MapFp2ToG2Sample, Bls12381MapFpToG1Run, Bls12381MapFpToG1Sample,
        Bls12381PairingRun, Bls12381PairingSample, Bls12381FpSerializeUncompressedRun
    },
    Host,
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

pub(crate) struct Bls12381G1ProjectiveToAffineMeasure;

impl HostCostMeasurement for Bls12381G1ProjectiveToAffineMeasure {
    type Runner = Bls12381G1ProjectiveToAffineRun;

    fn new_random_case(
        _host: &Host,
        rng: &mut StdRng,
        _input: u64,
    ) -> Bls12381G1ProjectiveToAffineSample {
        let p0 = G1Projective::rand(rng);
        Bls12381G1ProjectiveToAffineSample(p0)
    }
}

pub(crate) struct Bls12381G1MulMeasure;

impl HostCostMeasurement for Bls12381G1MulMeasure {
    type Runner = Bls12381G1MulRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381G1MulSample {
        let p = G1Affine::rand(rng);
        let s = Fr::rand(rng);
        Bls12381G1MulSample(p, s)
    }
}

pub(crate) struct Bls12381G1MsmMeasure;

impl HostCostMeasurement for Bls12381G1MsmMeasure {
    type Runner = Bls12381G1MsmRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, input: u64) -> Bls12381G1MsmSample {
        Bls12381G1MsmSample(
            (0..input)
                .into_iter()
                .map(|_| G1Affine::rand(rng))
                .collect(),
            (0..input).into_iter().map(|_| Fr::rand(rng)).collect(),
        )
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

pub(crate) struct Bls12381G2ProjectiveToAffineMeasure;

impl HostCostMeasurement for Bls12381G2ProjectiveToAffineMeasure {
    type Runner = Bls12381G2ProjectiveToAffineRun;

    fn new_random_case(
        _host: &Host,
        rng: &mut StdRng,
        _input: u64,
    ) -> Bls12381G2ProjectiveToAffineSample {
        let p0 = G2Projective::rand(rng);
        Bls12381G2ProjectiveToAffineSample(p0)
    }
}

pub(crate) struct Bls12381G2AddMeasure;

impl HostCostMeasurement for Bls12381G2AddMeasure {
    type Runner = Bls12381G2AddRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381G2AddSample {
        let p0 = G2Affine::rand(rng);
        let p1 = G2Affine::rand(rng);
        Bls12381G2AddSample(p0, p1)
    }
}

pub(crate) struct Bls12381G2MulMeasure;

impl HostCostMeasurement for Bls12381G2MulMeasure {
    type Runner = Bls12381G2MulRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381G2MulSample {
        let p = G2Affine::rand(rng);
        let s = Fr::rand(rng);
        Bls12381G2MulSample(p, s)
    }
}

pub(crate) struct Bls12381G2MsmMeasure;

impl HostCostMeasurement for Bls12381G2MsmMeasure {
    type Runner = Bls12381G2MsmRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, input: u64) -> Bls12381G2MsmSample {
        Bls12381G2MsmSample(
            (0..input)
                .into_iter()
                .map(|_| G2Affine::rand(rng))
                .collect(),
            (0..input).into_iter().map(|_| Fr::rand(rng)).collect(),
        )
    }
}

pub(crate) struct Bls12381MapFp2ToG2Measure;

impl HostCostMeasurement for Bls12381MapFp2ToG2Measure {
    type Runner = Bls12381MapFp2ToG2Run;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381MapFp2ToG2Sample {
        let fp2 = Fq2::rand(rng);
        Bls12381MapFp2ToG2Sample(fp2)
    }
}

pub(crate) struct Bls12381HashToG2Measure;

impl HostCostMeasurement for Bls12381HashToG2Measure {
    type Runner = Bls12381HashToG2Run;

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> Bls12381HashToG2Sample {
        let len = rng.gen_range(0..1000) as usize;
        let mut msg = vec![0u8; len];
        rng.fill(msg.as_mut_slice());
        Bls12381HashToG2Sample(msg)
    }
}

pub(crate) struct Bls12381PairingMeasure;

impl HostCostMeasurement for Bls12381PairingMeasure {
    type Runner = Bls12381PairingRun;

    fn new_random_case(_host: &Host, rng: &mut StdRng, input: u64) -> Bls12381PairingSample {
        Bls12381PairingSample(
            (0..input)
                .into_iter()
                .map(|_| G1Affine::rand(rng))
                .collect(),
            (0..input)
                .into_iter()
                .map(|_| G2Affine::rand(rng))
                .collect(),
        )
    }
}

pub(crate) struct Bls12381G1AffineSerializeUncompressedMeasure;
impl HostCostMeasurement for Bls12381G1AffineSerializeUncompressedMeasure {
    type Runner = Bls12381G1AffineSerializeUncompressedRun;
    fn new_random_case(host: &Host, rng: &mut StdRng, input: u64) -> G1Affine {
        G1Affine::rand(rng)
    }
}
pub(crate) struct Bls12381G2AffineSerializeUncompressedMeasure;
impl HostCostMeasurement for Bls12381G2AffineSerializeUncompressedMeasure {
    type Runner = Bls12381G2AffineSerializeUncompressedRun;
    fn new_random_case(host: &Host, rng: &mut StdRng, input: u64) -> G2Affine {
        G2Affine::rand(rng)
    }
}
pub(crate) struct Bls12381Fp12SerializeUncompressedMeasure;
impl HostCostMeasurement for Bls12381Fp12SerializeUncompressedMeasure {
    type Runner = Bls12381Fp12SerializeUncompressedRun;
    fn new_random_case(host: &Host, rng: &mut StdRng, input: u64) -> Fq12 {
        Fq12::rand(rng)
    }
}
pub(crate) struct Bls12381FpSerializeUncompressedMeasure;
impl HostCostMeasurement for Bls12381FpSerializeUncompressedMeasure {
    type Runner = Bls12381FpSerializeUncompressedRun;
    fn new_random_case(host: &Host, rng: &mut StdRng, input: u64) -> Fq {
        Fq::rand(rng)
    }
}

pub(crate) struct Bls12381G1AffineDeserializeUncompressedMeasure;
impl HostCostMeasurement for Bls12381G1AffineDeserializeUncompressedMeasure {
    type Runner = Bls12381G1AffineDeserializeUncompressedRun;
    fn new_random_case(
        host: &Host,
        rng: &mut StdRng,
        input: u64,
    ) -> Vec<u8>{
        let mut buf = vec![];
        let _ = G1Affine::rand(rng).serialize_uncompressed(&mut buf).unwrap();
        buf
    }
}
pub(crate) struct Bls12381G2AffineDeserializeUncompressedMeasure;
impl HostCostMeasurement for Bls12381G2AffineDeserializeUncompressedMeasure {
    type Runner = Bls12381G2AffineDeserializeUncompressedRun;
    fn new_random_case(
        host: &Host,
        rng: &mut StdRng,
        input: u64,
    ) -> Vec<u8>{
        let mut buf = vec![];
        let _ = G2Affine::rand(rng).serialize_uncompressed(&mut buf).unwrap();
        buf
    }
}
pub(crate) struct Bls12381FpDeserializeUncompressedMeasure;
impl HostCostMeasurement for Bls12381FpDeserializeUncompressedMeasure {
    type Runner = Bls12381FpDeserializeUncompressedRun;
    fn new_random_case(
        host: &Host,
        rng: &mut StdRng,
        input: u64,
    ) -> Vec<u8>{
        let mut buf = vec![];
        let _ = Fq::rand(rng).serialize_uncompressed(&mut buf).unwrap();
        buf
    }
}
pub(crate) struct Bls12381Fp2DeserializeUncompressedMeasure;
impl HostCostMeasurement for Bls12381Fp2DeserializeUncompressedMeasure {
    type Runner = Bls12381Fp2DeserializeUncompressedRun;
    fn new_random_case(
        host: &Host,
        rng: &mut StdRng,
        input: u64,
    ) -> Vec<u8>{
        let mut buf = vec![];
        let _ = Fq2::rand(rng).serialize_uncompressed(&mut buf).unwrap();
        buf
    }
}
