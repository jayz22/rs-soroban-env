use crate::Host;
use soroban_env_common::{CheckedEnv, RawVal};

#[test]
fn ok_proof() {
    let host = Host::default();
    let mut cards = host.test_vec_obj(&[5u32, 6, 10]).unwrap();
    let decision = host.test_vec_obj(&[1u32]).unwrap();
    let mut proof = host.prove(cards, decision).unwrap();
    let mut rv: RawVal = host.verify(proof, decision).unwrap();
    assert_eq!(rv.get_payload(), RawVal::from_bool(true).get_payload());

    cards = host.test_vec_obj(&[1u32, 1, 1]).unwrap();
    proof = host.prove(cards, decision).unwrap();
    rv = host.verify(proof, decision).unwrap();
    assert_eq!(rv.get_payload(), RawVal::from_bool(true).get_payload());
}

#[test]
fn ko_proof() {
    let host = Host::default();
    let cards = host.test_vec_obj(&[5u32, 6, 11]).unwrap();
    let mut decision = host.test_vec_obj(&[1u32]).unwrap();
    let mut proof = host.prove(cards, decision).unwrap();
    let mut rv: RawVal = host.verify(proof, decision).unwrap();
    assert_eq!(rv.get_payload(), RawVal::from_bool(false).get_payload());

    decision = host.test_vec_obj(&[5u32]).unwrap();
    proof = host.prove(cards, decision).unwrap();
    rv = host.verify(proof, decision).unwrap();
    assert_eq!(rv.get_payload(), RawVal::from_bool(false).get_payload());
}
