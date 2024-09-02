use crate::{budget::AsBudget, crypto::bls12_381, Host, HostError};
use ark_bls12_381::Fr;
use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes_lit::bytes;
use hex_literal::hex;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use soroban_env_common::{Env, EnvBase, U32Val};

const NUMBER_OF_SIGNERS: u32 = 10;

#[test]
fn test_fr_roundtrip() {
    // let mut rng = StdRng::from_seed([0xff; 32]);
    // let fr: Fr = Fr::rand(&mut rng);
    // println!("fr: {fr:?}");
    let fr = Fr::from(5u32);
    println!("fr: {fr:?}");

    let bi = fr.into_bigint(); // this converts the Montgomary backend into bigint, which performs the montgomary reduction first into a normal number
    println!("into_bigint: {bi:?}");
    println!("bigint bytes: {:?}", bi.to_bytes_le());

    let a = fr.0;
    println!("fr.0, which is the MontBackend: {a:?}");
    let b = a.to_bytes_le();
    println!("fr.0 bytes {:?}", b);

    let fr_back = Fr::from_le_bytes_mod_order(b.as_slice());
    println!("this is produced by taking fr.0 back, which doesn't match initial");
    println!("{fr_back:?}");

    let fr_back2 = Fr::from_le_bytes_mod_order(&bi.to_bytes_le());
    println!("this is produced by taking fr.into_bigint() back (which calls P:into_bigint(), which is MontBackend<FrConfig, 4> bigint), which matches original number");
    println!("{fr_back2:?}")
}

#[test]
fn key_gen() {
    let mut rng = StdRng::from_seed([0xff; 32]);
    let g1 = ark_bls12_381::G1Affine::generator();
    let mut g1_uncompressed = [0u8; 96];
    g1.serialize_uncompressed(g1_uncompressed.as_mut_slice())
        .unwrap();
    println!("G1 generator point: {}", hex::encode(g1_uncompressed));

    let neg_g1 = -g1;
    neg_g1
        .serialize_uncompressed(g1_uncompressed.as_mut_slice())
        .unwrap();
    println!(
        "Negative G1 generator point: {}",
        hex::encode(g1_uncompressed)
    );

    for i in 0..10 {
        let mut ikm = vec![0u8; 32];
        rng.fill_bytes(&mut ikm);
        let sk = bls_on_arkworks::keygen(&ikm);
        let sk_le_bytes = sk.into_bigint().to_bytes_be();
        println!("sk {i}: {}", hex::encode(sk_le_bytes));
        let pk = bls_on_arkworks::sk_to_pk(sk);
        let mut pk_uncompressed = [0u8; 96];
        ark_bls12_381::G1Affine::deserialize_compressed(pk.as_slice())
            .unwrap()
            .serialize_uncompressed(pk_uncompressed.as_mut_slice())
            .unwrap();
        println!("pk {i}: {}", hex::encode(pk_uncompressed));
    }

    let fr = ark_bls12_381::Fr::rand(&mut rng);
    let le_bytes = fr.into_bigint().to_bytes_le();
}

// #[test]
// fn test_sign_and_verify() -> Result<(), HostError> {
//     let host = Host::test_host();
//     host.enable_debug()?;
//     // let g1 = ark_bls12_381::G1Affine::generator();
//     // let g1_bytes_obj = host.g1_affine_serialize_uncompressed(g1).unwrap();
//     let g1 = host.bytes_new_from_slice(&bytes!(0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1))?;

//     let msg: Vec<u8> = "authorize payment in USDC".into();
//     let msg_bytes = host.bytes_new_from_slice(msg.as_slice())?;
//     let msg_hash_g2 = host.bls12_381_hash_to_g2(msg_bytes)?;
//     let sk = host.bytes_new_from_slice(&bytes!(
//         0xdc173661889ae052b017723bb9d295dad18226e16d470eed8e7dc6c611dec966
//     ))?;
//     let pk = host.bytes_new_from_slice(&bytes!(0x0914e32703bad05ccf4180e240e44e867b26580f36e09331997b2e9effe1f509b1a804fc7ba1f1334c8d41f060dd72550901c5549caef45212a236e288a785d762a087092c769bfa79611b96d73521ddd086b7e05b5c7e4210f50c2ee832e183))?;
//     let sig = host.bls12_381_g2_mul(msg_hash_g2, sk)?;

//     let lhs = host.bls12_381_pairing(g1, sig).unwrap();
//     let rhs = host.bls12_381_pairing(pk, msg_hash_g2).unwrap();

//     assert_eq!(host.obj_cmp(lhs.to_val(), rhs.to_val()).unwrap(), 0);
//     println!("{:?}", host.as_budget());

//     Ok(())
// }

// #[test]
// fn test_bls_verify_sig() -> Result<(), HostError> {
//     let host = Host::test_host();
//     host.enable_debug().unwrap();
//     let mut rng = StdRng::from_seed([0xff; 32]);
//     let g1 = ark_bls12_381::G1Affine::generator();
//     let g1_bytes_obj = host.g1_affine_serialize_uncompressed(g1).unwrap();

//     let msg: Vec<u8> = "authorize payment in USDC".into();
//     let dst: Vec<u8> = bls12_381::BLS12381_G2_DST.into();
//     let msg_bytes = host.bytes_new_from_slice(msg.as_slice()).unwrap();
//     let msg_hash_g2 = host.bls12_381_hash_to_g2(msg_bytes).unwrap();

//     let mut ikm = vec![0u8; 32];
//     rng.fill_bytes(&mut ikm);
//     let sk = bls_on_arkworks::keygen(&ikm);
//     println!("bls_on_arkworks sk: {sk:?}");
//     // {
//     //     let bts = hex::encode(sk.0.to_bytes_le());
//     //     println!("{bts:?}")
//     // }
//     let pk = bls_on_arkworks::sk_to_pk(sk);
//     let pk_bytes_obj = host
//         .g1_affine_serialize_uncompressed(
//             ark_bls12_381::G1Affine::deserialize_compressed(pk.as_slice()).unwrap(),
//         )
//         .unwrap();

//     // {
//     //     let sig = bls_on_arkworks::sign(sk, &msg, &dst).unwrap();
//     //     let sig_bytes_obj = host.g2_affine_serialize_uncompressed(ark_bls12_381::G2Affine::deserialize_compressed(sig.as_slice()).unwrap()).unwrap();
//     //     let mut buf = vec![0u8; 192];
//     //     host.bytes_copy_to_slice(sig_bytes_obj, U32Val::from(0) , buf.as_mut_slice())?;
//     //     println!("bls_on_arkworks sig: {}", hex::encode(buf));
//     // }

//     // get the bytes ourselves, convert to fp and mul ourselve
//     // doesn't work
//     let sk_le_bytes = host.bytes_new_from_slice(sk.into_bigint().to_bytes_le().as_slice())?;
//     let sig_bytes_obj = host.bls12_381_g2_mul(msg_hash_g2, sk_le_bytes)?;

//     // use the sk from them but do the multiplication ourselves
//     // {
//     //     let msg_p2 = host.g2_affine_deserialize_from_bytesobj(msg_hash_g2)?;
//     //     let sig_internal = host.g2_mul_internal(msg_p2, sk)?;
//     //     // println!("sig_internal: {sig_internal:?}")
//     //     let sig_bytes_obj = host.g2_projective_serialize_uncompressed(sig_internal)?;
//     // }

//     // {
//     //     let mut buf = vec![0u8; 192];
//     //     host.bytes_copy_to_slice(sig_bytes_obj.clone(), U32Val::from(0) , buf.as_mut_slice())?;
//     //     println!("my sig: {}", hex::encode(buf));
//     // }

//     let lhs = host.bls12_381_pairing(g1_bytes_obj, sig_bytes_obj).unwrap();
//     let rhs = host.bls12_381_pairing(pk_bytes_obj, msg_hash_g2).unwrap();

//     assert_eq!(host.obj_cmp(lhs.to_val(), rhs.to_val()).unwrap(), 0);
//     println!("{:?}", host.as_budget());
//     Ok(())
// }

// #[test]
// fn test_bls_aggregate_sig() {
//     let host = Host::test_host();
//     host.enable_debug().unwrap();
//     let mut rng = StdRng::from_seed([0xff; 32]);
//     let mut sks = vec![];
//     let mut pk_vec_bytes = vec![];
//     let mut sigs = vec![];

//     let msg: Vec<u8> = "authorize payment in USDC".into();
//     let dst: Vec<u8> = bls12_381::BLS12381_G2_DST.into();
//     let mut agg_sig: Vec<u8> = vec![];
//     for _i in 0..NUMBER_OF_SIGNERS {
//         let mut ikm = vec![0u8; 32];
//         rng.fill_bytes(&mut ikm);
//         let sk = bls_on_arkworks::keygen(&ikm);
//         let pk = bls_on_arkworks::sk_to_pk(sk);

//         let bo = host
//             .g1_affine_serialize_uncompressed(
//                 ark_bls12_381::G1Affine::deserialize_compressed(pk.as_slice()).unwrap(),
//             )
//             .unwrap();
//         pk_vec_bytes.push(bo);

//         sks.push(sk);
//         let sig = bls_on_arkworks::sign(sk, &msg, &dst).unwrap();
//         sigs.push(sig);
//         agg_sig = bls_on_arkworks::aggregate(&sigs).unwrap();
//     }

//     let g1 = ark_bls12_381::G1Affine::generator();
//     let g1_bytes = host.g1_affine_serialize_uncompressed(g1).unwrap();
//     let msg_bytes = host.bytes_new_from_slice(msg.as_slice()).unwrap();
//     let msg_hash_g2 = host.bls12_381_hash_to_g2(msg_bytes).unwrap();

//     let agg_sig_g2 = ark_bls12_381::G2Affine::deserialize_compressed(agg_sig.as_slice()).unwrap();
//     let agg_sig_bytes = host.g2_affine_serialize_uncompressed(agg_sig_g2).unwrap();

//     let mut agg_pk_bytes = pk_vec_bytes[0];
//     for i in 1..pk_vec_bytes.len() {
//         agg_pk_bytes = host
//             .bls12_381_g1_add(agg_pk_bytes, pk_vec_bytes[i])
//             .unwrap();
//     }

//     let lhs = host.bls12_381_pairing(g1_bytes, agg_sig_bytes).unwrap();
//     let rhs = host.bls12_381_pairing(agg_pk_bytes, msg_hash_g2).unwrap();
//     assert_eq!(host.obj_cmp(lhs.to_val(), rhs.to_val()).unwrap(), 0);
//     println!("{:?}", host.as_budget());
// }
