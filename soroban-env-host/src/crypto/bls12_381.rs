use std::{
    ops::{Add, Mul},
    rc::Rc,
};
use crate::host::metered_clone::MeteredContainer;
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
use ark_ec::short_weierstrass::{Affine, Projective};
use ark_ec::CurveGroup;
use sha2::Sha256;

use ark_bls12_381::{Bls12_381, Fr, G1Affine};
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
    One, PrimeField, UniformRand, Zero,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use soroban_env_common::{Env, TryFromVal, VecObject};

const G1_SERIALIZED_SIZE: usize = 48;
const G2_SERIALIZED_SIZE: usize = 96;
// Domain Separation Tags specified according to https://datatracker.ietf.org/doc/rfc9380/
// section 3.1, 8.8
const G1_DST: &'static str = "Soroban-V00-CS00-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
const G2_DST: &'static str = "Soroban-V00-CS00-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

impl Host {
    fn deserialize_from_bytesobj<T: CanonicalDeserialize>(
        &self,
        bo: BytesObject,
        expected_size: usize,
        msg: &str,
    ) -> Result<T, HostError> {
        self.visit_obj(bo, |bytes: &ScBytes| {
            if bytes.len() != expected_size {
                return Err(self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    format!("bls12-381 {msg}: invalid input length to deserialize").as_str(),
                    &[
                        Val::from_u32(bytes.len() as u32).into(),
                        Val::from_u32(expected_size as u32).into(),
                    ],
                ));
            }

            // TODO: metering charge for canonical deserialize with size
            self.charge_budget(ContractCostType::Sec1DecodePointUncompressed, None)?;
            T::deserialize_with_mode(bytes.as_slice(), Compress::No, Validate::Yes).map_err(|_e| {
                self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    "bls12-381: unable to deserialize",
                    &[],
                )
            })
        })
    }

    pub(crate) fn serialize_into_bytesobj<T: CanonicalSerialize>(
        &self,
        element: T,
        expected_size: usize,
        msg: &str,
    ) -> Result<BytesObject, HostError> {
        // TODO: metering charge canonical serializeation
        self.charge_budget(ContractCostType::ValSer, Some(expected_size as u64))?;
        let mut buf = vec![0; expected_size];        
        element
            .serialize_uncompressed(buf.as_mut_slice())
            .map_err(|_e| {
                self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InternalError,
                    format!("bls12-381: unable to serialize {msg}").as_str(),
                    &[],
                )
            })?;
        self.add_host_object(self.scbytes_from_vec(buf)?)
    }

    pub(crate) fn g1_affine_deserialize_from_bytesobj(
        &self,
        bo: BytesObject,
    ) -> Result<G1Affine, HostError> {
        self.deserialize_from_bytesobj(bo, 2 * G1_SERIALIZED_SIZE, "G1 affine")
    }

    pub(crate) fn g1_projective_into_affine(
        &self,
        g1: G1Projective,
    ) -> Result<G1Affine, HostError> {
        // TODO: metering charge g1projectiveintoaffine
        Ok(g1.into_affine())
    }

    pub(crate) fn g1_affine_serialize_uncompressed(
        &self,
        g1: G1Affine,
    ) -> Result<BytesObject, HostError> {
        self.serialize_into_bytesobj(g1, 2 * G1_SERIALIZED_SIZE, "G1 affine")
    }

    pub(crate) fn g1_projective_serialize_uncompressed(
        &self,
        g1: G1Projective,
    ) -> Result<BytesObject, HostError> {
        let g1_affine = self.g1_projective_into_affine(g1)?;
        self.g1_affine_serialize_uncompressed(g1_affine)
    }

    pub(crate) fn g2_affine_deserialize_from_bytesobj(
        &self,
        bo: BytesObject,
    ) -> Result<G2Affine, HostError> {
        self.deserialize_from_bytesobj(bo, 2 * G2_SERIALIZED_SIZE, "G2 affine")
    }

    pub(crate) fn g2_projective_into_affine(
        &self,
        g2: G2Projective,
    ) -> Result<G2Affine, HostError> {
        // TODO: metering charge g2projectiveintoaffine
        Ok(g2.into_affine())
    }

    pub(crate) fn g2_affine_serialize_uncompressed(
        &self,
        g2: G2Affine,
    ) -> Result<BytesObject, HostError> {
        self.serialize_into_bytesobj(g2, 2 * G2_SERIALIZED_SIZE, "G2 affine")
    }

    pub(crate) fn g2_projective_serialize_uncompressed(
        &self,
        g2: G2Projective,
    ) -> Result<BytesObject, HostError> {
        let g2_affine = self.g2_projective_into_affine(g2)?;
        self.g2_affine_serialize_uncompressed(g2_affine)
    }

    pub(crate) fn scalar_from_u256obj(&self, so: U256Object) -> Result<Fr, HostError> {
        // TODO: metering
        self.visit_obj(so, |scalar: &U256| {
            // the implementation of this function is in arc_ff prime.rs trait PrimeField. 
            // it performs some extra check if bytes is larger than the field size, which 
            // is not applicable to us. 
            // so the actual logic is just serializing a bytes array into a
            // Fp256<MontBackend<FrConfig, 4>>, which wraps a BigInt<4>. 
            // TODO: here we've assumed the input contains the exactly field element we want
            // should we instead provide from_random_bytes_with_flags? (ark_ff/fp/mod.rs)
            self.charge_budget(ContractCostType::ValDeser, Some(32))?;
            Ok(Fr::from_le_bytes_mod_order(&scalar.to_le_bytes()))
        })
    }

    pub(crate) fn fp_from_bytesobj(&self, bo: BytesObject) -> Result<Fq, HostError> {
        self.deserialize_from_bytesobj(bo, G1_SERIALIZED_SIZE, "field element (Fp)")
    }

    pub(crate) fn fp2_from_bytesobj(&self, bo: BytesObject) -> Result<Fq2, HostError> {
        self.deserialize_from_bytesobj(bo, G2_SERIALIZED_SIZE, "extention field element (Fp2)")
    }

    pub(crate) fn fp12_serialize(&self, fp12: Fq12) -> Result<BytesObject, HostError> {
        // TODO: verifty fp12 is always 576 bytes long
        self.serialize_into_bytesobj(fp12, 12 * G1_SERIALIZED_SIZE, "fp12")
    }

    fn g1_vec_from_vecobj(&self, vp: VecObject) -> Result<Vec<G1Affine>, HostError> {
        let len: u32 = self.vec_len(vp)?.into();
        let mut points: Vec<G1Affine> = vec![];
        // TODO: metering charge for memalloc
        points.reserve(len as usize);
        let _ = self.visit_obj(vp, |vp: &HostVec| {
            for p in vp.iter() {
                let pp = self.g1_affine_deserialize_from_bytesobj(
                    BytesObject::try_from_val(self, p)?,
                )?;
                points.push(pp);
            }
            Ok(())
        });
        Ok(points)
    }

    fn scalar_vec_from_vecobj(&self, vs: VecObject) -> Result<Vec<Fr>, HostError> {
        let len: u32 = self.vec_len(vs)?.into();
        let mut scalars: Vec<Fr> = vec![];
        // TODO: metering charge for memalloc
        scalars.reserve(len as usize);
        let _ = self.visit_obj(vs, |vs: &HostVec| {
            for s in vs.iter() {
                let ss = self.scalar_from_u256obj(U256Object::try_from_val(self, s)?)?;
                scalars.push(ss);
            }
            Ok(())
        });
        Ok(scalars)
    }

    pub(crate) fn g1_add_internal(&self, p0: G1Affine, p1: G1Affine) -> Result<G1Projective, HostError> {
        // TODO: metering
        Ok(p0.add(p1))
    }

    pub(crate) fn g1_mul_internal(&self, p0: G1Affine, scalar: Fr) -> Result<G1Projective, HostError> {
        // TODO: metering
        Ok(p0.mul(scalar))
    }

    pub(crate) fn g1_msm_from_vecobj(
        &self,
        vp: VecObject,
        vs: VecObject,
    ) -> Result<G1Projective, HostError> {
        // TODO: metering charge for msm, which can possibly be analytically composed of O(len) of scalar multiplication plus point addition
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
        let points = self.g1_vec_from_vecobj(vp)?;
        let scalars = self.scalar_vec_from_vecobj(vs)?;
        // TODO: metering. The actual logic happens inside msm_bigint_wnaf (ark_ec/variable_base/mod.rs)
        // under branch negation is cheap.
        // the unchecked version just skips the length equal check
        let res = G1Projective::msm_unchecked(points.as_slice(), scalars.as_slice());
        Ok(res)
    }

    pub(crate) fn map_fp_to_g1_internal(&self, fp: Fq) -> Result<G1Affine, HostError> {
        // TODO: metering
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

    pub(crate) fn hash_to_g1_internal<T: AsRef<[u8]>>(&self, msg: T) -> Result<G1Affine, HostError> {
        // TODO: metering
        let g1_mapper = MapToCurveBasedHasher::<
            Projective<g1::Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<g1::Config>,
        >::new(G1_DST.as_bytes())
        .map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })?;
        g1_mapper.hash(msg.as_ref()).map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })
    }

    fn g2_vec_from_vecobj(&self, vp: VecObject) -> Result<Vec<G2Affine>, HostError> {
        let len: u32 = self.vec_len(vp)?.into();
        // TODO: metering charge memalloc
        let mut points: Vec<G2Affine> = vec![];
        points.reserve(len as usize);
        let _ = self.visit_obj(vp, |vp: &HostVec| {
            for p in vp.iter() {
                let pp = self.g2_affine_deserialize_from_bytesobj(
                    BytesObject::try_from_val(self, p)?,
                )?;
                points.push(pp);
            }
            Ok(())
        });
        Ok(points)
    }


    pub(crate) fn g2_add_internal(&self, p0: G2Affine, p1: G2Affine) -> Result<G2Projective, HostError> {
        // TODO: metering
        Ok(p0.add(p1))
    }

    pub(crate) fn g2_mul_internal(&self, p0: G2Affine, scalar: Fr) -> Result<G2Projective, HostError> {
        // TODO: metering
        Ok(p0.mul(scalar))
    }

    pub(crate) fn g2_msm_from_vecobj(
        &self,
        vp: VecObject,
        vs: VecObject,
    ) -> Result<G2Projective, HostError> {
        // TODO: metering msm
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
        let points = self.g2_vec_from_vecobj(vp)?;
        let scalars = self.scalar_vec_from_vecobj(vs)?;
        let res = G2Projective::msm_unchecked(points.as_slice(), scalars.as_slice());
        Ok(res)
    }

    pub(crate) fn map_fp2_to_g2_internal(&self, fp: Fq2) -> Result<G2Affine, HostError> {
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

    pub(crate) fn hash_to_g2_internal<T: AsRef<[u8]>>(&self, msg: T) -> Result<G2Affine, HostError> {
        let mapper = MapToCurveBasedHasher::<
            Projective<g2::Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<g2::Config>,
        >::new(G2_DST.as_bytes())
        .map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })?;
        mapper.hash(msg.as_ref()).map_err(|e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("hash-to-curve error {e}").as_str(),
                &[],
            )
        })
    }

    pub(crate) fn pairing_internal(
        &self,
        p1: G1Affine,
        p2: G2Affine,
    ) -> Result<PairingOutput<Bls12_381>, HostError> {
        // TODO: metering
        let mlo = Bls12_381::multi_miller_loop([p1], [p2]);
        // TODO: metering
        Bls12_381::final_exponentiation(mlo).ok_or_else(|| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                "fail to perform final exponentiation",
                &[],
            )
        })
    }
}
