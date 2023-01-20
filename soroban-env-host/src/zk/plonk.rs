use dusk_bytes::Serializable;
use dusk_plonk::prelude::*;
use rand_core::OsRng;
use soroban_env_common::{EnvBase, Object, RawVal};
use std::fs;

use crate::host::Host;

use super::black_jack::BlackJack;

pub const PUBLIC_PARAMS: &'static [u8] = include_bytes!("data/public_params.bin").as_slice();
pub const PROVER_KEY: &'static [u8] = include_bytes!("data/prover.bin").as_slice();
pub const VERIFIER_DATA: &'static [u8] = include_bytes!("data/verifier.bin").as_slice();

pub struct Plonk;

impl Plonk {
    fn setup_pub_params(max_degree: usize) {
        let pp = PublicParameters::setup(max_degree, &mut OsRng).expect("failed to setup");
        let ser_pub_params = pp.to_raw_var_bytes();
        fs::write("data/public_params.bin", &ser_pub_params).expect("Unable to write file");
    }

    fn get_pub_params() -> PublicParameters {
        unsafe { PublicParameters::from_slice_unchecked(PUBLIC_PARAMS) }
    }

    fn setup_prover_verifier<C: Circuit>(mut circuit: C, pp: &PublicParameters) {
        let (prover, verifier) = circuit.compile(pp).expect("failed to compile circuit");
        let ser_prover = prover.to_var_bytes();
        fs::write("data/prover.bin", ser_prover.as_slice()).expect("Unable to write file");
        let ser_verifier = verifier.to_var_bytes();
        fs::write("data/verifier.bin", ser_verifier.as_slice()).expect("Unable to write file");
    }

    fn get_prover_key<C: Circuit>() -> ProverKey {
        ProverKey::from_slice(PROVER_KEY).expect("prover data corrupted")
    }

    fn get_verifier_data<C: Circuit>() -> VerifierData {
        VerifierData::from_slice(VERIFIER_DATA).expect("verifier data corrupted")
    }

    pub(crate) fn generate_proof(host: &Host, a: u32, b: u32, c: u32, d: u32) -> Object {
        let mut circuit = BlackJack {
            a: BlsScalar::from(a as u64),
            b: BlsScalar::from(b as u64),
            c: BlsScalar::from(c as u64),
            d: BlsScalar::from(d as u64),
        };
        let pp = Plonk::get_pub_params();
        let pk = Plonk::get_prover_key::<BlackJack>();
        let proof = circuit.prove(&pp, &pk, b"blackjack", &mut OsRng).unwrap();
        // let bytes = proof.to_bytes();
        host.bytes_new_from_slice(&proof.to_bytes()).unwrap()
    }

    pub(crate) fn verify_proof(host: &Host, bytes: &[u8], pi: u32) -> RawVal {
        let proof_bytes: &[u8; 1040] = bytes.try_into().expect("unexpected proof size");
        let proof = Proof::from_bytes(proof_bytes).expect("unable to extract proof from bytes");
        let public_inputs: Vec<PublicInputValue> = vec![BlsScalar::from(pi as u64).into()];
        let pp = Plonk::get_pub_params();
        let vd = Plonk::get_verifier_data::<BlackJack>();
        match BlackJack::verify(&pp, &vd, &proof, &public_inputs, b"blackjack") {
            Ok(_) => true.into(),
            Err(_) => false.into(),
        }
    }
}
