use crate::Host;
use soroban_env_common::{CheckedEnv, RawVal};

#[test]
fn ok_proof() {
    let host = Host::default();
    let cards = host.test_vec_obj(&[5u32, 6, 10]).unwrap();
    let target = host.test_vec_obj(&[21u32]).unwrap();
    let proof = host.prove(cards, target).unwrap();
    let rv: RawVal = host.verify(proof, target).unwrap();
    assert_eq!(rv.get_payload(), RawVal::from_bool(true).get_payload());
}

#[test]
fn ko_proof() {
    let host = Host::default();
    let cards = host.test_vec_obj(&[2u32, 6, 10]).unwrap();
    let target = host.test_vec_obj(&[21u32]).unwrap();
    let proof = host.prove(cards, target).unwrap();
    let rv: RawVal = host.verify(proof, target).unwrap();
    assert_eq!(rv.get_payload(), RawVal::from_bool(false).get_payload());
}
