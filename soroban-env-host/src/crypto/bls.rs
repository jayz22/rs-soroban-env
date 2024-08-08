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
use ark_ec::short_weierstrass::Projective;
use sha2::Sha256;


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
