use super::metered_clone::MeteredContainer;
use crate::host::prng::SEED_BYTES;
use crate::host_object::{HostVec, MemHostObjectType};
use crate::{
    budget::AsBudget,
    err,
    num::U256,
    xdr::{ContractCostType, Hash, ScBytes, ScErrorCode, ScErrorType},
    BytesObject, Error, Host, HostError, U256Object, U32Val, Val,
};
use ark_bls12_381::{g1, g2, Fq, Fq12, Fq2, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::short_weierstrass::Projective;
use elliptic_curve::scalar::IsHigh;
use hex_literal::hex;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use sha3::Keccak256;

use ecdsa::{signature::hazmat::PrehashVerifier, PrimeCurve, Signature, SignatureSize};
use elliptic_curve::CurveArithmetic;
use generic_array::ArrayLength;

use ark_bls12_381::{
    util::{G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE},
    Bls12_381, Fr, G1Affine,
};
use ark_ec::{
    hashing::{
        curve_maps::wb::WBMap,
        map_to_curve_hasher::{MapToCurve, MapToCurveBasedHasher},
        HashToCurve,
    },
    pairing,
    scalar_mul::variable_base::VariableBaseMSM,
};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    fields::Field,
    One, UniformRand, Zero,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use soroban_env_common::{Env, TryFromVal, VecObject};

// Domain Separation Tags specified according to https://datatracker.ietf.org/doc/rfc9380/, see sections 3.1, 8.8
const fn dst(order: u8) -> &'static str {
    match order {
        1 => "Soroban-V00-CS00-with-BLS12381G1_XMD:SHA-256_SSWU_RO_",
        2 => "Soroban-V00-CS00-with-BLS12381G2_XMD:SHA-256_SSWU_RO_",
        _ => "unsupported",
    }
}

impl Host {
    // Ed25519 functions
    pub(crate) fn ed25519_signature_from_bytesobj_input(
        &self,
        name: &'static str,
        sig: BytesObject,
    ) -> Result<ed25519_dalek::Signature, HostError> {
        self.fixed_length_bytes_from_bytesobj_input::<ed25519_dalek::Signature, {ed25519_dalek::SIGNATURE_LENGTH}>(name, sig)
    }

    pub(crate) fn ed25519_pub_key_from_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<ed25519_dalek::VerifyingKey, HostError> {
        self.charge_budget(ContractCostType::ComputeEd25519PubKey, None)?;
        let vk_bytes = bytes.try_into().map_err(|_| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "invalid length of ed25519 public key",
                &[Val::from_u32(bytes.len() as u32).into()],
            )
        })?;
        ed25519_dalek::VerifyingKey::from_bytes(vk_bytes).map_err(|_| {
            err!(
                self,
                (ScErrorType::Crypto, ScErrorCode::InvalidInput),
                "invalid ed25519 public key",
                bytes
            )
        })
    }

    pub(crate) fn ed25519_pub_key_from_bytesobj_input(
        &self,
        k: BytesObject,
    ) -> Result<ed25519_dalek::VerifyingKey, HostError> {
        self.visit_obj(k, |bytes: &ScBytes| {
            self.ed25519_pub_key_from_bytes(bytes.as_slice())
        })
    }

    pub(crate) fn verify_sig_ed25519_internal(
        &self,
        payload: &[u8],
        verifying_key: &ed25519_dalek::VerifyingKey,
        sig: &ed25519_dalek::Signature,
    ) -> Result<(), HostError> {
        let _span = tracy_span!("ed25519 verify");
        self.charge_budget(
            ContractCostType::VerifyEd25519Sig,
            Some(payload.len() as u64),
        )?;
        verifying_key.verify_strict(payload, sig).map_err(|_| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "failed ED25519 verification",
                &[],
            )
        })
    }

    pub(crate) fn secp256r1_verify_signature(
        &self,
        verifying_key: &p256::ecdsa::VerifyingKey,
        msg_hash: &Hash,
        sig: &Signature<p256::NistP256>,
    ) -> Result<(), HostError> {
        let _span = tracy_span!("p256 verify");
        self.charge_budget(ContractCostType::VerifyEcdsaSecp256r1Sig, None)?;
        verifying_key
            .verify_prehash(msg_hash.as_slice(), sig)
            .map_err(|_| {
                self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    "failed secp256r1 verification",
                    &[],
                )
            })
    }

    pub(crate) fn secp256r1_decode_sec1_uncompressed_pubkey(
        &self,
        bytes: &[u8],
    ) -> Result<p256::ecdsa::VerifyingKey, HostError> {
        use sec1::point::Tag;
        self.charge_budget(ContractCostType::Sec1DecodePointUncompressed, None)?;
        // check and make sure the key was encoded in uncompressed format
        let tag = bytes
            .first()
            .copied()
            .ok_or(sec1::Error::PointEncoding)
            .and_then(Tag::from_u8)
            .map_err(|_| {
                self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    "invalid ECDSA public key",
                    &[],
                )
            })?;
        if tag != Tag::Uncompressed {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "invalid ECDSA public key",
                &[],
            ));
        }

        p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes).map_err(|_| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "invalid ECDSA public key",
                &[],
            )
        })
    }

    pub(crate) fn secp256r1_public_key_from_bytesobj_input(
        &self,
        k: BytesObject,
    ) -> Result<p256::ecdsa::VerifyingKey, HostError> {
        self.visit_obj(k, |bytes: &ScBytes| {
            self.secp256r1_decode_sec1_uncompressed_pubkey(bytes.as_slice())
        })
    }

    // ECDSA functions
    pub(crate) fn ecdsa_signature_from_bytes<C>(
        &self,
        bytes: &[u8],
    ) -> Result<Signature<C>, HostError>
    where
        C: PrimeCurve + CurveArithmetic,
        SignatureSize<C>: ArrayLength<u8>,
    {
        self.charge_budget(ContractCostType::DecodeEcdsaCurve256Sig, None)?;
        let sig = Signature::<C>::try_from(bytes).map_err(|_| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "invalid ECDSA sinature",
                &[],
            )
        })?;
        if sig.s().is_high().into() {
            Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "ECDSA signature 's' part is not normalized to low form",
                &[],
            ))
        } else {
            Ok(sig)
        }
    }

    pub(crate) fn ecdsa_signature_from_bytesobj_input<C>(
        &self,
        k: BytesObject,
    ) -> Result<Signature<C>, HostError>
    where
        C: PrimeCurve + CurveArithmetic,
        SignatureSize<C>: ArrayLength<u8>,
    {
        self.visit_obj(k, |bytes: &ScBytes| {
            self.ecdsa_signature_from_bytes(bytes.as_slice())
        })
    }

    // ECDSA secp256k1 functions

    // NB: not metered as it's a trivial constant cost, just converting a byte to a byte,
    // and always done exactly once as part of the secp256k1 recovery path.
    pub(crate) fn secp256k1_recovery_id_from_u32val(
        &self,
        recovery_id: U32Val,
    ) -> Result<k256::ecdsa::RecoveryId, HostError> {
        let rid32: u32 = u32::from(recovery_id);
        if rid32 > k256::ecdsa::RecoveryId::MAX as u32 {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "invalid ECDSA-secp256k1 recovery ID",
                &[recovery_id.to_val()],
            ));
        }
        k256::ecdsa::RecoveryId::try_from(rid32 as u8).map_err(|_| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "invalid ECDSA-secp256k1 recovery ID",
                &[recovery_id.to_val()],
            )
        })
    }

    pub(crate) fn recover_key_ecdsa_secp256k1_internal(
        &self,
        hash: &Hash,
        sig: &k256::ecdsa::Signature,
        rid: k256::ecdsa::RecoveryId,
    ) -> Result<ScBytes, HostError> {
        let _span = tracy_span!("secp256k1 recover");
        self.charge_budget(ContractCostType::RecoverEcdsaSecp256k1Key, None)?;
        let recovered_key =
            k256::ecdsa::VerifyingKey::recover_from_prehash(hash.as_slice(), &sig, rid).map_err(
                |_| {
                    self.err(
                        ScErrorType::Crypto,
                        ScErrorCode::InvalidInput,
                        "ECDSA-secp256k1 signature recovery failed",
                        &[],
                    )
                },
            )?;
        Ok(ScBytes::from(crate::xdr::BytesM::try_from(
            recovered_key
                .to_encoded_point(/*compress:*/ false)
                .as_bytes(),
        )?))
    }

    // SHA256 functions

    pub(crate) fn sha256_hash_from_bytesobj_input(
        &self,
        x: BytesObject,
    ) -> Result<Vec<u8>, HostError> {
        self.visit_obj(x, |bytes: &ScBytes| {
            let hash = sha256_hash_from_bytes(bytes.as_slice(), self)?;
            if hash.len() != 32 {
                return Err(err!(
                    self,
                    (ScErrorType::Object, ScErrorCode::UnexpectedSize),
                    "expected 32-byte BytesObject for sha256 hash, got different size",
                    hash.len()
                ));
            }
            Ok(hash)
        })
    }

    // Keccak256/SHA3 functions
    pub(crate) fn keccak256_hash_from_bytes_raw(
        &self,
        bytes: &[u8],
    ) -> Result<[u8; 32], HostError> {
        let _span = tracy_span!("keccak256");
        self.charge_budget(
            ContractCostType::ComputeKeccak256Hash,
            Some(bytes.len() as u64),
        )?;
        Ok(<Keccak256 as sha3::Digest>::digest(bytes).into())
    }

    pub(crate) fn keccak256_hash_from_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, HostError> {
        Vec::<u8>::charge_bulk_init_cpy(32, self.as_budget())?;
        self.keccak256_hash_from_bytes_raw(bytes)
            .map(|x| x.to_vec())
    }

    pub(crate) fn keccak256_hash_from_bytesobj_input(
        &self,
        x: BytesObject,
    ) -> Result<Vec<u8>, HostError> {
        self.visit_obj(x, |bytes: &ScBytes| {
            let hash = self.keccak256_hash_from_bytes(bytes.as_slice())?;
            if hash.len() != 32 {
                return Err(err!(
                    self,
                    (ScErrorType::Object, ScErrorCode::UnexpectedSize),
                    "expected 32-byte BytesObject for keccak256 hash, got different size",
                    hash.len()
                ));
            }
            Ok(hash)
        })
    }

    pub(crate) fn bls12_381_g1_uncompressed_from_bytesobj(
        &self,
        bo: BytesObject,
    ) -> Result<G1Affine, HostError> {
        self.visit_obj(bo, |g1: &ScBytes| {
            if g1.len() != 2 * G1_SERIALIZED_SIZE {
                return Err(self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    "invalid length of an uncompressed bls12-381 G1Affine point",
                    &[Val::from_u32(g1.len() as u32).into()],
                ));
            }
            G1Affine::deserialize_uncompressed(g1.as_byte_slice()).map_err(|_e| {
                self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    "unable to deserialize g1",
                    &[bo.to_val()],
                )
            })
        })
    }

    pub(crate) fn bls12_381_g1_serialize_uncompressed(
        &self,
        g1: G1Projective,
    ) -> Result<BytesObject, HostError> {
        let mut buf = vec![0; 2 * G1_SERIALIZED_SIZE];
        g1.serialize_uncompressed(buf.as_mut_slice())
            .map_err(|_e| {
                self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InternalError,
                    "unable to serialize g1",
                    &[],
                )
            })?;
        self.add_host_object(self.scbytes_from_vec(buf)?)
    }

    pub(crate) fn bls12_381_scalar_from_u256obj(&self, so: U256Object) -> Result<Fr, HostError> {
        self.visit_obj(so, |scalar: &U256| {
            Ok(Fr::from_le_bytes_mod_order(&scalar.to_le_bytes()))
        })
    }

    pub(crate) fn bls12_381_fp_from_bytesobj(&self, fp: BytesObject) -> Result<Fq, HostError> {
        self.visit_obj(fp, |fp: &ScBytes| {
            if fp.len() != G1_SERIALIZED_SIZE {
                return Err(self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    "invalid length of a bls12-381 field element",
                    &[Val::from_u32(fp.len() as u32).into()],
                ));
            }
            Fq::deserialize_uncompressed(fp.as_slice()).map_err(|e| {
                self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    "unable to deserialize bls12-381 field element",
                    &[],
                )
            })
        })
    }

    fn bls12_381_g1_vec_from_vecobj(&self, vp: VecObject) -> Result<Vec<G1Affine>, HostError> {
        let len: u32 = self.vec_len(vp)?.into();
        let mut points: Vec<G1Affine> = vec![];
        points.reserve(len as usize);
        self.visit_obj(vp, |vp: &HostVec| {
            for p in vp.iter() {
                let pp = self
                    .bls12_381_g1_uncompressed_from_bytesobj(BytesObject::try_from_val(self, p)?)?;
                points.push(pp);
            }
            Ok(())
        });
        Ok(points)
    }

    fn bls12_381_scalar_vec_from_vecobj(&self, vs: VecObject) -> Result<Vec<Fr>, HostError> {
        let len: u32 = self.vec_len(vs)?.into();
        let mut scalars: Vec<Fr> = vec![];
        scalars.reserve(len as usize);
        self.visit_obj(vs, |vs: &HostVec| {
            for s in vs.iter() {
                let ss = self.bls12_381_scalar_from_u256obj(U256Object::try_from_val(self, s)?)?;
                scalars.push(ss);
            }
            Ok(())
        });
        Ok(scalars)
    }

    pub(crate) fn bls12_381_g1_msm_from_vecobj(
        &self,
        vp: VecObject,
        vs: VecObject,
    ) -> Result<G1Projective, HostError> {
        let p_len = self.vec_len(vp)?;
        let s_len = self.vec_len(vs)?;
        if u32::from(p_len) != u32::from(s_len) {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                "length mismatch for g1 msm",
                &[p_len.to_val(), s_len.to_val()],
            ));
        }
        let points = self.bls12_381_g1_vec_from_vecobj(vp)?;
        let scalars = self.bls12_381_scalar_vec_from_vecobj(vs)?;
        let res = G1Projective::msm_unchecked(points.as_slice(), scalars.as_slice());
        Ok(res)
    }

    pub(crate) fn bls12_381_map_fp_to_g1_internal(&self, fp: Fq) -> Result<G1Affine, HostError> {
        let dst = dst(1).as_bytes();
        debug_assert!(dst.len() <= 255, "Domain separator exceeds length limit");
        let mapper = WBMap::<g1::Config>::new().map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })?;
        mapper.map_to_curve(fp).map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })
    }

    pub(crate) fn bls12_381_hash_to_g1_internal(&self, msg: &[u8]) -> Result<G1Affine, HostError> {
        let dst = dst(1).as_bytes();
        debug_assert!(dst.len() <= 255, "Domain separator exceeds length limit");
        let g1_mapper = MapToCurveBasedHasher::<
            Projective<g1::Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<g1::Config>,
        >::new(dst)
        .map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })?;
        g1_mapper.hash(msg).map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })
    }

    pub(crate) fn bls12_381_g2_uncompressed_from_bytesobj(
        &self,
        bo: BytesObject,
    ) -> Result<G2Affine, HostError> {
        self.visit_obj(bo, |g2: &ScBytes| {
            if g2.len() != 2 * G2_SERIALIZED_SIZE {
                return Err(self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    "invalid length of an uncompressed bls12-381 G2Affine point",
                    &[Val::from_u32(g2.len() as u32).into()],
                ));
            }
            G2Affine::deserialize_uncompressed(g2.as_byte_slice()).map_err(|_e| {
                self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    "unable to deserialize g2",
                    &[bo.to_val()],
                )
            })
        })
    }

    pub(crate) fn bls12_381_g2_serialize_uncompressed(
        &self,
        g2: G2Projective,
    ) -> Result<BytesObject, HostError> {
        let mut buf = vec![0; 2 * G2_SERIALIZED_SIZE];
        g2.serialize_uncompressed(buf.as_mut_slice())
            .map_err(|_e| {
                self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InternalError,
                    "unable to serialize g2",
                    &[],
                )
            })?;
        self.add_host_object(self.scbytes_from_vec(buf)?)
    }

    fn bls12_381_g2_vec_from_vecobj(&self, vp: VecObject) -> Result<Vec<G2Affine>, HostError> {
        let len: u32 = self.vec_len(vp)?.into();
        let mut points: Vec<G2Affine> = vec![];
        points.reserve(len as usize);
        self.visit_obj(vp, |vp: &HostVec| {
            for p in vp.iter() {
                let pp = self
                    .bls12_381_g2_uncompressed_from_bytesobj(BytesObject::try_from_val(self, p)?)?;
                points.push(pp);
            }
            Ok(())
        });
        Ok(points)
    }

    pub(crate) fn bls12_381_g2_msm_from_vecobj(
        &self,
        vp: VecObject,
        vs: VecObject,
    ) -> Result<G2Projective, HostError> {
        let p_len = self.vec_len(vp)?;
        let s_len = self.vec_len(vs)?;
        if u32::from(p_len) != u32::from(s_len) {
            return Err(self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                "length mismatch for g2 msm",
                &[p_len.to_val(), s_len.to_val()],
            ));
        }
        let points = self.bls12_381_g2_vec_from_vecobj(vp)?;
        let scalars = self.bls12_381_scalar_vec_from_vecobj(vs)?;
        let res = G2Projective::msm_unchecked(points.as_slice(), scalars.as_slice());
        Ok(res)
    }

    pub(crate) fn bls12_381_map_fp2_to_g2_internal(&self, fp: Fq2) -> Result<G2Affine, HostError> {
        let dst = dst(2).as_bytes();
        debug_assert!(dst.len() <= 255, "Domain separator exceeds length limit");
        let mapper = WBMap::<g2::Config>::new().map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })?;
        mapper.map_to_curve(fp).map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })
    }

    pub(crate) fn bls12_381_hash_to_g2_internal(&self, msg: &[u8]) -> Result<G2Affine, HostError> {
        let dst = dst(2).as_bytes();
        debug_assert!(dst.len() <= 255, "Domain separator exceeds length limit");
        let mapper = MapToCurveBasedHasher::<
            Projective<g2::Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<g2::Config>,
        >::new(dst)
        .map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })?;
        mapper.hash(msg).map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })
    }

    pub(crate) fn bls12_381_pairing_internal(
        &self,
        p1: G1Affine,
        p2: G2Affine,
    ) -> Result<PairingOutput<Bls12_381>, HostError> {
        let mlo = Bls12_381::multi_miller_loop([p1], [p2]);
        Bls12_381::final_exponentiation(mlo).ok_or_else(|| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                "fail to perform final exponentiation",
                &[],
            )
        })
    }

    pub(crate) fn bls12_381_fp12_serialize(&self, fp12: Fq12) -> Result<BytesObject, HostError> {
        // TODO: I believe fp12 is always 576 bytes long, we can use a static buffer here.
        let mut buf = vec![];
        fp12.serialize_uncompressed(buf.as_mut_slice())
            .map_err(|_e| {
                self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InternalError,
                    "unable to serialize fp12",
                    &[],
                )
            })?;
        self.add_host_object(self.scbytes_from_vec(buf)?)
    }
}

pub(crate) fn sha256_hash_from_bytes_raw(
    bytes: &[u8],
    budget: impl AsBudget,
) -> Result<[u8; 32], HostError> {
    let _span = tracy_span!("sha256");
    budget.as_budget().charge(
        ContractCostType::ComputeSha256Hash,
        Some(bytes.len() as u64),
    )?;
    Ok(<Sha256 as sha2::Digest>::digest(bytes).into())
}

pub(crate) fn sha256_hash_from_bytes(
    bytes: &[u8],
    budget: impl AsBudget,
) -> Result<Vec<u8>, HostError> {
    Vec::<u8>::charge_bulk_init_cpy(32, budget.clone())?;
    sha256_hash_from_bytes_raw(bytes, budget).map(|x| x.to_vec())
}

pub(crate) fn chacha20_fill_bytes(
    rng: &mut ChaCha20Rng,
    dest: &mut [u8],
    budget: impl AsBudget,
) -> Result<(), HostError> {
    tracy_span!("chacha20");
    budget
        .as_budget()
        .charge(ContractCostType::ChaCha20DrawBytes, Some(dest.len() as u64))?;
    rng.fill_bytes(dest);
    Ok(())
}

// It is possible that a user-provided PRNG seed (either in a test or, more
// worryingly, in a production environment) is biased: it might be all zero, or
// all copies of a single byte, or otherwise statistically unlike a uniformly
// random bitstream with roughly 50-50 zero and one bits.
//
// Unfortunately the security properties of the stream cipher ChaCha used in the
// PRNG (being "indistinguishable from uniform random") are based on the
// assumption of an _unbiased_ seed.
//
// So we run any seed through HMAC-SHA256 here, with a constant uniform random
// salt, as an unbiasing step (this is the "randomness-extractor" phase of HKDF,
// which is the only part relevant to our needs, we don't need multiple keys).

pub(crate) fn unbias_prng_seed(
    seed: &[u8; SEED_BYTES as usize],
    budget: impl AsBudget,
) -> Result<[u8; SEED_BYTES as usize], HostError> {
    tracy_span!("unbias_prng_seed");

    // Salt is fixed and must not be changed; it is effectively "part of the
    // protocol" and must be the same for all implementations.
    //
    // Note: salt is a "public random value", intended to be statistically
    // similar to a 32-byte draw on /dev/random but done in a transparent and
    // reproducible way. In this case we use the Stellar Public Network ID,
    // `sha256("Public Global Stellar Network ; September 2015")`.
    //
    // This number as a bitstring has 137 zeroes and 119 ones, which is within
    // the range we get when taking 32-byte samples from /dev/random (feel free
    // to check this yourself).

    const SALT: [u8; 32] = hex!("7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979");

    // Running HMAC will run SHA256 2 times on 64 bytes each time (32-byte salt
    // concatenated with 32-byte input).
    budget
        .as_budget()
        .bulk_charge(ContractCostType::ComputeSha256Hash, 2, Some(64))?;

    let mut hmac = Hmac::<Sha256>::new_from_slice(&SALT)
        .map_err(|_| Error::from_type_and_code(ScErrorType::Context, ScErrorCode::InternalError))?;
    hmac.update(seed);
    Ok(hmac.finalize().into_bytes().into())
}
