use std::cmp::Ordering;

use crate::{
    crypto::bls12_381::{self, G1_SERIALIZED_SIZE},
    xdr::{ScErrorCode, ScErrorType},
    BytesObject, Env, EnvBase, Error, Host, HostError, U32Val, Val,
};
use ark_bls12_381::{Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes_lit::bytes;
use hex::{FromHex, ToHex};
use hex_literal::hex;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use soroban_env_common::{U256Val, VecObject};

enum InvalidPointTypes {
    TooManyBytes,
    TooFewBytes,
    CompressionFlagSet,
    InfinityFlagSetBitsNotAllZero,
    SortFlagSet,
    PointNotOnCurve,
    PointNotInSubgroup,
}

use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct Field {
    m: String,
    p: String,
}

#[derive(Deserialize, Debug)]
struct Map {
    name: String,
}

#[derive(Deserialize, Debug)]
struct Point {
    x: String,
    y: String,
}

#[derive(Deserialize, Debug)]
struct TestCase {
    P: Point,
    Q0: Point,
    Q1: Point,
    msg: String,
    u: [String; 2],
}

#[derive(Deserialize, Debug)]
struct HashToCurveTestSuite {
    L: String,
    Z: String,
    ciphersuite: String,
    curve: String,
    dst: String,
    expand: String,
    field: Field,
    hash: String,
    k: String,
    map: Map,
    randomOracle: bool,
    vectors: Vec<TestCase>,
}

// Domain Separation Tags specified according to https://datatracker.ietf.org/doc/rfc9380/
// section 3.1, 8.8
// NB: "_RO_" here stands for "random oracle", the alternative is "_NU_" which
// stands for "non-uniform". The difference is encoding type. `_RO_` provides
// stronger security guarantees by ensuring that output is uniformly distributed
// accross the curve. In terms of algorithmic details, `_NU_` is idential to
// `_RO_` except that the encoding type is `encode_to_curve` instead of
// `hash_to_curve`.
pub const BLS12381_G1_DST: &'static str = "SOROBAN-V01-CS01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
pub const BLS12381_G2_DST: &'static str = "SOROBAN-V01-CS01-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

fn parse_hex(s: String) -> Vec<u8> {
    Vec::from_hex(s.trim_start_matches("0x")).unwrap()
}

fn sample_g1_not_on_curve(host: &Host) -> Result<BytesObject, HostError> {
    let mut rng = StdRng::from_seed([0xff; 32]);
    loop {
        let x = Fq::rand(&mut rng);
        let y = Fq::rand(&mut rng);
        let p = G1Affine::new_unchecked(x, y);
        if !p.is_on_curve() {
            return host.g1_affine_serialize_uncompressed(p);
        }
    }
}

fn sample_g1_not_in_subgroup(host: &Host) -> Result<BytesObject, HostError> {
    let mut rng = StdRng::from_seed([0xff; 32]);
    loop {
        let x = Fq::rand(&mut rng);
        if let Some(p) = G1Affine::get_point_from_x_unchecked(x, true) {
            assert!(p.is_on_curve());
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                return host.g1_affine_serialize_uncompressed(p);
            }
        }
    }
}

fn sample_g1(host: &Host) -> Result<BytesObject, HostError> {
    let mut rng = StdRng::from_seed([0xff; 32]);
    host.g1_affine_serialize_uncompressed(G1Affine::rand(&mut rng))
}

fn g1_zero(host: &Host) -> Result<BytesObject, HostError> {
    host.g1_affine_serialize_uncompressed(G1Affine::zero())
}

fn neg_g1(bo: BytesObject, host: &Host) -> Result<BytesObject, HostError> {
    let g1 = host.g1_affine_deserialize_from_bytesobj(bo)?;
    host.g1_affine_serialize_uncompressed(-g1)
}

fn invalid_g1(host: &Host, ty: InvalidPointTypes) -> Result<BytesObject, HostError> {
    let mut rng = StdRng::from_seed([0xff; 32]);
    let affine = G1Affine::rand(&mut rng);
    assert!(!affine.is_zero());
    let bo = host.g1_affine_serialize_uncompressed(affine)?;
    match ty {
        InvalidPointTypes::TooManyBytes => {
            // insert an empty byte to the end
            host.bytes_insert(bo, U32Val::from(48), U32Val::from(0))
        }
        InvalidPointTypes::TooFewBytes => {
            // delete the last byte
            host.bytes_del(bo, U32Val::from(47))
        }
        InvalidPointTypes::CompressionFlagSet => {
            let mut first_byte: u32 = host.bytes_get(bo, U32Val::from(0))?.into();
            first_byte = ((first_byte as u8) | (1 << 7)) as u32;
            host.bytes_put(bo, U32Val::from(0), U32Val::from(first_byte))
        }
        InvalidPointTypes::InfinityFlagSetBitsNotAllZero => {
            let mut first_byte: u32 = host.bytes_get(bo, U32Val::from(0))?.into();
            first_byte = ((first_byte as u8) | (1 << 6)) as u32;
            host.bytes_put(bo, U32Val::from(0), U32Val::from(first_byte))
        }
        InvalidPointTypes::SortFlagSet => {
            let mut first_byte: u32 = host.bytes_get(bo, U32Val::from(0))?.into();
            first_byte = ((first_byte as u8) | (1 << 5)) as u32;
            host.bytes_put(bo, U32Val::from(0), U32Val::from(first_byte))
        }
        InvalidPointTypes::PointNotOnCurve => sample_g1_not_on_curve(host),
        InvalidPointTypes::PointNotInSubgroup => sample_g1_not_in_subgroup(host),
    }
}

fn invalid_g2(ty: InvalidPointTypes) -> G1Affine {
    match ty {
        InvalidPointTypes::TooManyBytes => todo!(),
        InvalidPointTypes::TooFewBytes => todo!(),
        InvalidPointTypes::CompressionFlagSet => todo!(),
        InvalidPointTypes::SortFlagSet => todo!(),
        InvalidPointTypes::InfinityFlagSetBitsNotAllZero => todo!(),
        InvalidPointTypes::PointNotOnCurve => todo!(),
        InvalidPointTypes::PointNotInSubgroup => todo!(),
    }
    todo!()
}

fn sample_fp(host: &Host) -> Result<BytesObject, HostError> {
    let mut rng = StdRng::from_seed([0xff; 32]);
    let fp = Fq::rand(&mut rng);
    let mut buf = [0u8; 48];
    host.serialize_into_bytesobj(&fp, &mut buf, 1, "test")?;
    host.bytes_new_from_slice(&buf)
}

fn invalid_fp(host: &Host, ty: InvalidPointTypes) -> Result<BytesObject, HostError> {
    let mut rng = StdRng::from_seed([0xff; 32]);
    let fp = Fq::rand(&mut rng);
    match ty {
        InvalidPointTypes::TooManyBytes => {
            let mut buf = [0u8; 49]; // one extra zero byte
            host.serialize_into_bytesobj(&fp, &mut buf, 1, "test")?;
            host.bytes_new_from_slice(&buf)
        }
        InvalidPointTypes::TooFewBytes => {
            let mut buf = [0u8; 48];
            host.serialize_into_bytesobj(&fp, &mut buf, 1, "test")?;
            host.bytes_new_from_slice(&buf[0..47]) // only take 47 bytes
        }
        _ => panic!("not available"),
    }
}

fn sample_fr(host: &Host) -> Result<U256Val, HostError> {
    let mut rng = StdRng::from_seed([0xff; 32]);
    let obj = host.obj_from_u256_pieces(
        u64::rand(&mut rng),
        u64::rand(&mut rng),
        u64::rand(&mut rng),
        u64::rand(&mut rng),
    )?;
    Ok(obj.into())
}

fn sample_host_vec<T: UniformRand + CanonicalSerialize>(
    host: &Host,
    buf_size: usize,
    vec_len: usize,
) -> Result<VecObject, HostError> {
    let mut rng = StdRng::from_seed([0xff; 32]);
    let vals: Vec<Val> = (0..vec_len)
        .into_iter()
        .map(|_| {
            let t = T::rand(&mut rng);
            let mut buf = vec![0; buf_size];
            host.serialize_into_bytesobj(&t, &mut buf, 1, "test")
                .unwrap();
            host.bytes_new_from_slice(&buf).unwrap().to_val()
        })
        .collect();
    host.vec_new_from_slice(&vals)
}

fn sample_fr_vec(host: &Host, vec_len: usize) -> Result<VecObject, HostError> {
    let mut rng = StdRng::from_seed([0xff; 32]);
    let vals: Vec<Val> = (0..vec_len)
        .into_iter()
        .map(|_| {
            host.obj_from_u256_pieces(
                u64::rand(&mut rng),
                u64::rand(&mut rng),
                u64::rand(&mut rng),
                u64::rand(&mut rng),
            )
            .unwrap()
            .to_val()
        })
        .collect();
    host.vec_new_from_slice(&vals)
}

#[test]
fn g1_add() -> Result<(), HostError> {
    // let host = observe_host!(Host::test_host());
    let host = Host::test_host();
    host.enable_debug()?;
    // invalid p1
    {
        let p2 = sample_g1(&host)?;
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(invalid_g1(&host, InvalidPointTypes::TooManyBytes)?, p2),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(invalid_g1(&host, InvalidPointTypes::TooFewBytes)?, p2),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(
                invalid_g1(&host, InvalidPointTypes::CompressionFlagSet)?,
                p2
            ),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(
                invalid_g1(&host, InvalidPointTypes::InfinityFlagSetBitsNotAllZero)?,
                p2
            ),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(invalid_g1(&host, InvalidPointTypes::SortFlagSet)?, p2),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(invalid_g1(&host, InvalidPointTypes::PointNotOnCurve)?, p2),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(
                invalid_g1(&host, InvalidPointTypes::PointNotInSubgroup)?,
                p2
            ),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        // let diags = host.get_diagnostic_events()?;
        // println!("{diags:?}")
    }
    // invalid p2
    {
        let p1 = sample_g1(&host)?;
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(p1, invalid_g1(&host, InvalidPointTypes::TooManyBytes)?),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(p1, invalid_g1(&host, InvalidPointTypes::TooFewBytes)?),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(
                p1,
                invalid_g1(&host, InvalidPointTypes::CompressionFlagSet)?
            ),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(
                p1,
                invalid_g1(&host, InvalidPointTypes::InfinityFlagSetBitsNotAllZero)?
            ),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(p1, invalid_g1(&host, InvalidPointTypes::SortFlagSet)?),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(p1, invalid_g1(&host, InvalidPointTypes::PointNotOnCurve)?),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_add(
                p1,
                invalid_g1(&host, InvalidPointTypes::PointNotInSubgroup)?
            ),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
    }
    // 3. lhs.add(zero) = lhs
    {
        let p1 = sample_g1(&host)?;
        let res = host.bls12_381_g1_add(p1, g1_zero(&host)?)?;
        assert_eq!(host.obj_cmp(p1.into(), res.into())?, Ordering::Equal as i64);
    }
    // 4. zero.add(rhs) = rhs
    {
        let p2 = sample_g1(&host)?;
        let res = host.bls12_381_g1_add(g1_zero(&host)?, p2)?;
        assert_eq!(host.obj_cmp(p2.into(), res.into())?, Ordering::Equal as i64);
    }
    // 5. communitive a + b = b + a
    {
        let a = sample_g1(&host)?;
        let b = sample_g1(&host)?;
        let a_plus_b = host.bls12_381_g1_add(a, b)?;
        let b_plus_a = host.bls12_381_g1_add(b, a)?;
        assert_eq!(
            host.obj_cmp(a_plus_b.into(), b_plus_a.into())?,
            Ordering::Equal as i64
        );
    }
    // 6. associative (a + b) + c = a + (b + c)
    {
        let a = sample_g1(&host)?;
        let b = sample_g1(&host)?;
        let c = sample_g1(&host)?;
        let aplusb = host.bls12_381_g1_add(a, b)?;
        let aplusb_plus_c = host.bls12_381_g1_add(aplusb, c)?;
        let bplusc = host.bls12_381_g1_add(b, c)?;
        let a_plus_bplusc = host.bls12_381_g1_add(a, bplusc)?;
        assert_eq!(
            host.obj_cmp(aplusb_plus_c.into(), a_plus_bplusc.into())?,
            Ordering::Equal as i64
        );
    }
    // 7. a - a = zero
    {
        let a = sample_g1(&host)?;
        let neg_a = neg_g1(a.clone(), &host)?;
        let res = host.bls12_381_g1_add(a, neg_a)?;
        let zero = g1_zero(&host)?;
        assert_eq!(
            host.obj_cmp(res.into(), zero.into())?,
            Ordering::Equal as i64
        );
    }
    Ok(())
}

#[test]
fn g1_mul() -> Result<(), HostError> {
    // let host = observe_host!(Host::test_host());
    let host = Host::test_host();
    host.enable_debug()?;
    // 2. lhs * 0 = 0
    {
        let lhs = sample_g1(&host)?;
        let rhs = host.obj_from_u256_pieces(0, 0, 0, 0)?;
        let res = host.bls12_381_g1_mul(lhs, rhs.into())?;
        let zero = g1_zero(&host)?;
        assert_eq!(
            host.obj_cmp(res.into(), zero.into())?,
            Ordering::Equal as i64
        );
    }
    // 3. lhs * 1 = lhs
    {
        let lhs = sample_g1(&host)?;
        let rhs = U256Val::from_u32(1);
        let res = host.bls12_381_g1_mul(lhs, rhs.into())?;
        assert_eq!(
            host.obj_cmp(res.into(), lhs.into())?,
            Ordering::Equal as i64
        );
    }
    // 4. associative P * a * b = P * b * a
    {
        let p = sample_g1(&host)?;
        let a = sample_fr(&host)?;
        let b = sample_fr(&host)?;
        let pa = host.bls12_381_g1_mul(p, a)?;
        let pab = host.bls12_381_g1_mul(pa, b)?;
        let pb = host.bls12_381_g1_mul(p, b)?;
        let pba = host.bls12_381_g1_mul(pb, a)?;
        assert_eq!(
            host.obj_cmp(pab.into(), pba.into())?,
            Ordering::Equal as i64
        );
    }
    Ok(())
}

#[test]
fn g1_msm() -> Result<(), HostError> {
    // let host = observe_host!(Host::test_host());
    let host = Host::test_host();
    host.enable_debug()?;
    // vector lengths are zero
    {
        let vp = host.vec_new()?;
        let vs = host.vec_new()?;
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_msm(vp, vs),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
    }
    // vector lengths not equal
    {
        let vp =
            host.vec_new_from_slice(&[sample_g1(&host)?.to_val(), sample_g1(&host)?.to_val()])?;
        let vs = host.vec_new_from_slice(&[
            sample_fr(&host)?.to_val(),
            sample_fr(&host)?.to_val(),
            sample_fr(&host)?.to_val(),
        ])?;
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_msm(vp, vs),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
    }
    // vector g1 not valid
    {
        let vp = host.vec_new_from_slice(&[
            sample_g1(&host)?.to_val(),
            invalid_g1(&host, InvalidPointTypes::PointNotInSubgroup)?.to_val(),
            sample_g1(&host)?.to_val(),
        ])?;
        let vs = host.vec_new_from_slice(&[
            sample_fr(&host)?.to_val(),
            sample_fr(&host)?.to_val(),
            sample_fr(&host)?.to_val(),
        ])?;
        assert!(HostError::result_matches_err(
            host.bls12_381_g1_msm(vp, vs),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
    }
    // vector of zero points result zero
    {
        let vp = host.vec_new_from_slice(&[g1_zero(&host)?.to_val(); 3])?;
        let vs = host.vec_new_from_slice(&[
            sample_fr(&host)?.to_val(),
            sample_fr(&host)?.to_val(),
            sample_fr(&host)?.to_val(),
        ])?;
        let res = host.bls12_381_g1_msm(vp, vs)?;
        assert_eq!(
            host.obj_cmp(res.into(), g1_zero(&host)?.into())?,
            Ordering::Equal as i64
        );
    }
    // vector of zero scalars result in zero point
    {
        let vp = sample_host_vec::<G1Affine>(&host, G1_SERIALIZED_SIZE, 3)?;
        let vs = host.vec_new_from_slice(&[U256Val::from_u32(0).to_val(); 3])?;
        let res = host.bls12_381_g1_msm(vp, vs)?;
        assert_eq!(
            host.obj_cmp(res.into(), g1_zero(&host)?.into())?,
            Ordering::Equal as i64
        );
    }
    // 6. g1 * (1) + g1 (-1) = 0
    {
        let pt = sample_g1(&host)?;
        let zero = g1_zero(&host)?;
        assert_ne!(
            host.obj_cmp(pt.into(), zero.into())?,
            Ordering::Equal as i64
        );
        let neg_pt = neg_g1(pt, &host)?;
        let vp = host.vec_new_from_slice(&[pt.to_val(), neg_pt.to_val()])?;
        let vs = host.vec_new_from_slice(&[U256Val::from_u32(1).to_val(); 2])?;
        let res = host.bls12_381_g1_msm(vp, vs)?;
        assert_eq!(
            host.obj_cmp(res.into(), g1_zero(&host)?.into())?,
            Ordering::Equal as i64
        );
    }
    // 7. associative: shuffle points orders results stay the same
    {
        host.budget_ref().reset_default()?;
        let mut vp = vec![
            sample_g1(&host)?.to_val(),
            sample_g1(&host)?.to_val(),
            sample_g1(&host)?.to_val(),
            sample_g1(&host)?.to_val(),
        ];
        let mut vs = vec![
            sample_fr(&host)?.to_val(),
            sample_fr(&host)?.to_val(),
            sample_fr(&host)?.to_val(),
            sample_fr(&host)?.to_val(),
        ];
        let ref_res =
            host.bls12_381_g1_msm(host.vec_new_from_slice(&vp)?, host.vec_new_from_slice(&vs)?)?;
        let mut rng = StdRng::from_seed([0xff; 32]);
        let mut shuffle_with_order = |v1: &mut Vec<Val>, v2: &mut Vec<Val>| {
            use rand::seq::SliceRandom;
            assert_eq!(v1.len(), v2.len());
            let mut indices: Vec<usize> = (0..v1.len()).collect();
            indices.shuffle(&mut rng);
            let v1_shuffled: Vec<Val> = indices.iter().map(|&i| v1[i]).collect();
            let v2_shuffled: Vec<Val> = indices.iter().map(|&i| v2[i]).collect();
            *v1 = v1_shuffled;
            *v2 = v2_shuffled;
        };

        for _ in 0..10 {
            shuffle_with_order(&mut vp, &mut vs);
            let vp_obj = host.vec_new_from_slice(&vp)?;
            let vs_obj = host.vec_new_from_slice(&vs)?;
            let res = host.bls12_381_g1_msm(vp_obj, vs_obj)?;
            assert_eq!(
                host.obj_cmp(res.into(), ref_res.into())?,
                Ordering::Equal as i64
            );
        }
    }
    // 8. msm result is same as invidial mul and add
    {
        host.budget_ref().reset_default()?;
        let vp = sample_host_vec::<G1Affine>(&host, G1_SERIALIZED_SIZE, 10)?;
        let vs = sample_fr_vec(&host, 10)?;
        let ref_res = host.bls12_381_g1_msm(vp, vs)?;
        let mut res = g1_zero(&host)?;
        for i in 0..10 {
            let p: BytesObject = host.vec_get(vp, U32Val::from(i))?.try_into()?;
            let s: U256Val = host.vec_get(vs, U32Val::from(i))?.try_into()?;
            let rhs = host.bls12_381_g1_mul(p, s)?;
            res = host.bls12_381_g1_add(res, rhs)?;
        }
        assert_eq!(
            host.obj_cmp(res.into(), ref_res.into())?,
            Ordering::Equal as i64
        );
    }
    Ok(())
}

#[test]
fn map_fp_to_g1() -> Result<(), HostError> {
    // let host = observe_host!(Host::test_host());
    let host = Host::test_host();
    host.enable_debug()?;
    // invalid fp: wrongth length
    {
        let fp1 = invalid_fp(&host, InvalidPointTypes::TooFewBytes)?;
        assert!(HostError::result_matches_err(
            host.bls12_381_map_fp_to_g1(fp1),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
        let fp2 = invalid_fp(&host, InvalidPointTypes::TooManyBytes)?;
        assert!(HostError::result_matches_err(
            host.bls12_381_map_fp_to_g1(fp2),
            (ScErrorType::Crypto, ScErrorCode::InvalidInput)
        ));
    }
    // Test cases from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#name-bls12381g1_xmdsha-256_sswu_
    // To interpret the results, understand the steps it takes to hash a msg to curve
    //   1. u = hash_to_field(msg, 2)
    //   2. Q0 = map_to_curve(u[0])
    //   3. Q1 = map_to_curve(u[1])
    //   4. R = Q0 + Q1 # Point addition
    //   5. P = clear_cofactor(R)
    //   6. return P
    {
        host.budget_ref().reset_default()?;
        let test_map_fp_to_curve_inner = |u: String, q: Point| -> Result<(), HostError> {
            let mut q_bytes = [0u8; 96];
            q_bytes[0..48].copy_from_slice(&parse_hex(q.x));
            q_bytes[48..].copy_from_slice(&parse_hex(q.y));
            let g1 = host.bytes_new_from_slice(&q_bytes)?;
            let fp = host.bytes_new_from_slice(&parse_hex(u))?;
            let res = host.bls12_381_map_fp_to_g1(fp)?;
            assert_eq!(host.obj_cmp(res.into(), g1.into())?, Ordering::Equal as i64);
            Ok(())
        };

        let test_suite: HashToCurveTestSuite = serde_json::from_slice(
            &std::fs::read("./src/test/data/BLS12381G1_XMD_SHA-256_SSWU_RO_.json").unwrap(),
        )
        .unwrap();
        println!("{test_suite:?}");
        for case in test_suite.vectors {
            let [u0, u1] = case.u;
            test_map_fp_to_curve_inner(u0, case.Q0)?;
            test_map_fp_to_curve_inner(u1, case.Q1)?;
        }
    }
    Ok(())
}

#[test]
fn hash_to_g1() -> Result<(), HostError> {
    // let host = observe_host!(Host::test_host());
    let host = Host::test_host();
    host.enable_debug()?;
    let test_suite: HashToCurveTestSuite = serde_json::from_slice(
        &std::fs::read("./src/test/data/BLS12381G1_XMD_SHA-256_SSWU_RO_.json").unwrap(),
    )
    .unwrap();
    let dst = host.bytes_new_from_slice(test_suite.dst.as_bytes())?;
    let parse_g1 = |p: Point| -> Result<BytesObject, HostError> {
        let mut p_bytes = [0u8; 96];
        p_bytes[0..48].copy_from_slice(&parse_hex(p.x));
        p_bytes[48..].copy_from_slice(&parse_hex(p.y));
        host.bytes_new_from_slice(&p_bytes)
    };

    for case in test_suite.vectors {
        let msg = host.bytes_new_from_slice(case.msg.as_bytes())?;
        let g1 = host.bls12_381_hash_to_g1(msg, dst)?;
        let g1_ref = parse_g1(case.P)?;
        assert_eq!(
            host.obj_cmp(g1.into(), g1_ref.into())?,
            Ordering::Equal as i64
        );
    }
    Ok(())
}

// g2 tests, same as g1

// pairing checks
#[test]
fn pairing() -> Result<(), HostError> {
    // vectors don't match
    // vector length is 0
    // any g1 is invalid
    // any g2 is invalid
    // e(c*A, B) == e(A, c*B) = c * e(A, B)
    // e(A + B, C + D) = e(A, C) * e(B, C) * e(A, D) * e(B, D)
    Ok(())
}

// fr arithmetics

// serialization roundtrip

// bls signature

// ethereum test

// fuzzing tests
