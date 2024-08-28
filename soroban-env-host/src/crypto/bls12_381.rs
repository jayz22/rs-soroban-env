use crate::host_object::HostVec;
use crate::{
    budget::AsBudget,
    xdr::{ContractCostType, ScBytes, ScErrorCode, ScErrorType},
    Bool, BytesObject, Host, HostError, Val,
};
use ark_bls12_381::{g1, g2, Fq, Fq12, Fq2, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::short_weierstrass::Projective;
use ark_ec::CurveGroup;
use ark_ff::{Field, BigInteger};
use sha2::Sha256;
use std::cmp::Ordering;
use std::ops::{Add, Mul, AddAssign, MulAssign, SubAssign};
use num_traits::Zero;

use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::{
    hashing::{
        curve_maps::wb::WBMap,
        map_to_curve_hasher::{MapToCurve, MapToCurveBasedHasher},
        HashToCurve,
    },
    scalar_mul::variable_base::VariableBaseMSM,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate, Valid};
use soroban_env_common::{ConversionError, Env, TryFromVal, U256Object, U256Small, U256Val, VecObject, U256};

const G1_SERIALIZED_SIZE: usize = 48;
const G2_SERIALIZED_SIZE: usize = 96;
// Domain Separation Tags specified according to https://datatracker.ietf.org/doc/rfc9380/
// section 3.1, 8.8
pub const BLS12381_G1_DST: &'static str = "Soroban-V00-CS00-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
pub const BLS12381_G2_DST: &'static str = "Soroban-V00-CS00-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

//============================================================================
// Some preliminary calibration results
//============================================================================
// | Cost Type                          |      CPU |   equivalent wasm insns  |
// |:-----------------------------------|---------:|-------------------------:|
// | Bls12381FpSerializeUncompressed    |      987 |                     247  |
// | Bls12381FpDeserializeUncompressed  |     1058 |                     265  |
// | Bls12381G1ProjectiveToAffine       |    88023 |                   22006  |
// | Bls12381G1Add                      |     7281 |                    1821  |
// | Bls12381G1Mul                      |  2277752 |                  569438  |
// | Bls12381MapFpToG1                  |  1510142 |                  377536  |
// | Bls12381HashToG1                   |  3192885 |                  798222  |
// | Bls12381G2ProjectiveToAffine       |    95994 |                   24000  |
// | Bls12381G2Add                      |    23570 |                    5893  |
// | Bls12381G2Mul                      |  7075352 |                 1768838  |
// | Bls12381MapFp2ToG2                 |  2367368 |                  591842  |
// | Bls12381HashToG2                   |  6870057 |                 1717515  |
//========================================================================


// | Cost Type               | CPU (const) | CPU (lin)   |   | eqv. wasm insns eqv. InstantiateWasmDataSegmentBytes |
// |:------------------------|------------:|------------:|-  |----------------:-----------------------------------:|
// | Bls12381G1Msm            |    2214244  |  109110682  |   |          553561                           7793621  |
// | Bls12381G2Msm            |    7226943  |  336724933  |   |         1806736                          24051781  |
// | Bls12381Pairing          |    9852690  |  586227065  |   |         2463173                          41873362  |


enum ExperimentalCostType {
    Bls12381FpSerializeUncompressed,
    Bls12381FpDeserializeUncompressed,
    Bls12381G1ProjectiveToAffine,
    Bls12381G1Add,
    Bls12381G1Mul,
    Bls12381G1Msm,
    Bls12381MapFpToG1,
    Bls12381HashToG1,
    Bls12381G2ProjectiveToAffine,
    Bls12381G2Add,
    Bls12381G2Mul,
    Bls12381G2Msm,
    Bls12381MapFp2ToG2,
    Bls12381HashToG2,
    Bls12381Pairing,
}

// each wasm insn is calibrated to be 4 cpu insns
// based on the calibration results shown above, we convert the cpu count into
// number of equivalent wasm insns.
// The whole point is to work without XDR definition of these new types
fn equivalent_wasm_insns(ty: ExperimentalCostType) -> u64 {
    match ty {
        ExperimentalCostType::Bls12381FpSerializeUncompressed => 247,
        ExperimentalCostType::Bls12381FpDeserializeUncompressed => 265,
        ExperimentalCostType::Bls12381G1ProjectiveToAffine => 22006,
        ExperimentalCostType::Bls12381G1Add => 1821,
        ExperimentalCostType::Bls12381G1Mul => 569438,
        ExperimentalCostType::Bls12381G1Msm => 553561,
        ExperimentalCostType::Bls12381MapFpToG1 => 377536,
        ExperimentalCostType::Bls12381HashToG1 => 798222,
        ExperimentalCostType::Bls12381G2ProjectiveToAffine => 24000,
        ExperimentalCostType::Bls12381G2Add => 5893,
        ExperimentalCostType::Bls12381G2Mul => 1768838,
        ExperimentalCostType::Bls12381G2Msm => 1806736,
        ExperimentalCostType::Bls12381MapFp2ToG2 => 591842,
        ExperimentalCostType::Bls12381HashToG2 => 1717515,
        ExperimentalCostType::Bls12381Pairing => 2463173,
    }
}

fn equivalent_instantiate_wasm_data_segment_bytes(ty: ExperimentalCostType) -> u64 {
    match ty {
        ExperimentalCostType::Bls12381G1Msm => 7793621,
        ExperimentalCostType::Bls12381G2Msm => 24051781,
        ExperimentalCostType::Bls12381Pairing => 41873362,
        _ => 0
    }
}

impl Host {
    pub(crate) fn deserialize_uncompessed_no_validate<T: CanonicalDeserialize>(
        &self,
        slice: &[u8],
        ty: ContractCostType,
    ) -> Result<T, HostError> {
        self.charge_budget(ty, None)?;
        // validation turned off here to isolate the cost of serialization.
        // proper validation has to be performed outside of this function
        T::deserialize_with_mode(slice, Compress::No, Validate::No).map_err(|_e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "bls12-381: unable to deserialize",
                &[],
            )
        })
    }

    pub(crate) fn serialize_into_bytesobj<T: CanonicalSerialize>(
        &self,
        element: T,
        buf: &mut [u8],
        ty: ContractCostType,
        msg: &str,
    ) -> Result<(), HostError> {
        self.charge_budget(ty, None)?;
        element.serialize_uncompressed(buf).map_err(|_e| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                format!("bls12-381: unable to serialize {msg}").as_str(),
                &[],
            )
        })?;
        Ok(())
    }

    pub(crate) fn g1_affine_deserialize_from_bytesobj(
        &self,
        bo: BytesObject,
    ) -> Result<G1Affine, HostError> {
        let expected_size = 2 * G1_SERIALIZED_SIZE;
        let g1: G1Affine = self.visit_obj(bo, |bytes: &ScBytes| {
            if bytes.len() != expected_size {
                return Err(self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    format!("bls12-381 G1 affine: invalid input length to deserialize").as_str(),
                    &[
                        Val::from_u32(bytes.len() as u32).into(),
                        Val::from_u32(expected_size as u32).into(),
                    ],
                ));
            }
            // TODO: replace with actual cost type xdr
            self.deserialize_uncompessed_no_validate(&bytes, ContractCostType::Sec1DecodePointUncompressed)
        })?;
        // TODO: charge for point validation
        if g1.check().is_err() {
            Err(self.err(ScErrorType::Crypto, ScErrorCode::InvalidInput, "bls12-381 G1 affine deserialize: invalid point", &[]))
        } else {
            Ok(g1)
        }
    }

    pub(crate) fn g1_projective_into_affine(
        &self,
        g1: G1Projective,
    ) -> Result<G1Affine, HostError> {
        // TODO: metering charge g1projectiveintoaffine
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381G1ProjectiveToAffine),
            None,
        )?;
        Ok(g1.into_affine())
    }

    pub(crate) fn g1_affine_serialize_uncompressed(
        &self,
        g1: G1Affine,
    ) -> Result<BytesObject, HostError> {
        let mut buf = vec![0; 2 * G1_SERIALIZED_SIZE];
        // TODO: charge for the actual cost type xdr
        self.serialize_into_bytesobj(
            g1,
            &mut buf,
            ContractCostType::Sec1DecodePointUncompressed,
            "G1 affine",
        )?;
        self.add_host_object(self.scbytes_from_vec(buf)?)
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
        let expected_size = 2 * G2_SERIALIZED_SIZE;
        let g2: G2Affine = self.visit_obj(bo, |bytes: &ScBytes| {
            if bytes.len() != expected_size {
                return Err(self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    format!("bls12-381 G2 affine: invalid input length to deserialize").as_str(),
                    &[
                        Val::from_u32(bytes.len() as u32).into(),
                        Val::from_u32(expected_size as u32).into(),
                    ],
                ));
            }
            // TODO: replace with actual cost type xdr
            self.deserialize_uncompessed_no_validate(&bytes, ContractCostType::Sec1DecodePointUncompressed)
        })?;
        // TODO: charge for point validation
        if g2.check().is_err() {
            Err(self.err(ScErrorType::Crypto, ScErrorCode::InvalidInput, "bls12-381 G2 affine deserialize: invalid point", &[]))
        } else {
            Ok(g2)
        }        
    }

    pub(crate) fn g2_projective_into_affine(
        &self,
        g2: G2Projective,
    ) -> Result<G2Affine, HostError> {
        // TODO: metering charge g2projectiveintoaffine
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381G2ProjectiveToAffine),
            None,
        )?;
        Ok(g2.into_affine())
    }

    pub(crate) fn g2_affine_serialize_uncompressed(
        &self,
        g2: G2Affine,
    ) -> Result<BytesObject, HostError> {
        let mut buf = vec![0; 2 * G2_SERIALIZED_SIZE];
        // TODO: charge for the actual cost type xdr
        self.serialize_into_bytesobj(
            g2,
            &mut buf,
            ContractCostType::Sec1DecodePointUncompressed,
            "G2 affine",
        )?;
        self.add_host_object(self.scbytes_from_vec(buf)?)
    }

    pub(crate) fn g2_projective_serialize_uncompressed(
        &self,
        g2: G2Projective,
    ) -> Result<BytesObject, HostError> {
        let g2_affine = self.g2_projective_into_affine(g2)?;
        self.g2_affine_serialize_uncompressed(g2_affine)
    }

    pub(crate) fn scalar_from_u256val(&self, sv: U256Val) -> Result<Fr, HostError> {
        // TODO: metering.
        let fr = if let Ok(small) = U256Small::try_from(sv) {
            Fr::from_le_bytes_mod_order(&u64::from(small).to_le_bytes())
        } else {
            let obj: U256Object = sv.try_into()?;
            self.visit_obj(obj, |u: &U256| {
                Ok(Fr::from_le_bytes_mod_order(&u.to_le_bytes()))
            })?
        };
        Ok(fr)
    }

    pub(crate) fn scalar_to_u256val(&self, scalar: Fr) -> Result<U256Val, HostError> {
        let bytes: [u8; 32] = scalar.into_bigint().to_bytes_be().try_into().map_err(|_| HostError::from(ConversionError))?;
        let u = U256::from_be_bytes(bytes);
        self.map_err(U256Val::try_from_val(self, &u))
    }

    pub(crate) fn fp_deserialize_from_bytesobj(&self, bo: BytesObject) -> Result<Fq, HostError> {
        let expected_size = 2 * G1_SERIALIZED_SIZE;
        self.visit_obj(bo, |bytes: &ScBytes| {
            if bytes.len() != expected_size {
                return Err(self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    format!("bls12-381 field element (Fp): invalid input length to deserialize")
                        .as_str(),
                    &[
                        Val::from_u32(bytes.len() as u32).into(),
                        Val::from_u32(expected_size as u32).into(),
                    ],
                ));
            }
            // TODO: replace with actual cost type xdr
            self.deserialize_uncompessed_no_validate(&bytes, ContractCostType::Sec1DecodePointUncompressed)
        })
    }

    pub(crate) fn fp2_deserialize_from_bytesobj(&self, bo: BytesObject) -> Result<Fq2, HostError> {
        let expected_size = 2 * G2_SERIALIZED_SIZE;
        self.visit_obj(bo, |bytes: &ScBytes| {
            if bytes.len() != expected_size {
                return Err(self.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    format!("bls12-381 quadradic extention field element (Fp2): invalid input length to deserialize").as_str(),
                    &[
                        Val::from_u32(bytes.len() as u32).into(),
                        Val::from_u32(expected_size as u32).into(),
                    ],
                ));
            }
            // TODO: replace with actual cost type xdr
            self.deserialize_uncompessed_no_validate(&bytes, ContractCostType::Sec1DecodePointUncompressed)
        })
    }

    // TODO: generic vec_T_from_vecobj
    pub(crate) fn g1_vec_from_vecobj(&self, vp: VecObject) -> Result<Vec<G1Affine>, HostError> {
        let len: u32 = self.vec_len(vp)?.into();
        let mut points: Vec<G1Affine> = vec![];
        // TODO: metering charge for memalloc
        points.reserve(len as usize);
        let _ = self.visit_obj(vp, |vp: &HostVec| {
            for p in vp.iter() {
                let pp =
                    self.g1_affine_deserialize_from_bytesobj(BytesObject::try_from_val(self, p)?)?;
                points.push(pp);
            }
            Ok(())
        });
        Ok(points)
    }

    pub(crate) fn scalar_vec_from_vecobj(&self, vs: VecObject) -> Result<Vec<Fr>, HostError> {
        let len: u32 = self.vec_len(vs)?.into();
        let mut scalars: Vec<Fr> = vec![];
        // TODO: metering charge for memalloc
        scalars.reserve(len as usize);
        let _ = self.visit_obj(vs, |vs: &HostVec| {
            for s in vs.iter() {
                let ss = self.scalar_from_u256val(U256Val::try_from_val(self, s)?)?;
                scalars.push(ss);
            }
            Ok(())
        });
        Ok(scalars)
    }

    pub(crate) fn g1_add_internal(
        &self,
        p0: G1Affine,
        p1: G1Affine,
    ) -> Result<G1Projective, HostError> {
        // TODO: metering
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381G1Add),
            None,
        )?;
        Ok(p0.add(p1))
    }

    pub(crate) fn g1_mul_internal(
        &self,
        p0: G1Affine,
        scalar: Fr,
    ) -> Result<G1Projective, HostError> {
        // TODO: metering
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381G1Mul),
            None,
        )?;
        Ok(p0.mul(scalar))
    }

    pub(crate) fn g1_msm_internal(
        &self,
        points: &[G1Affine],
        scalars: &[Fr],
    ) -> Result<G1Projective, HostError> {
        // TODO: metering. The actual logic happens inside msm_bigint_wnaf (ark_ec/variable_base/mod.rs)
        // under branch negation is cheap.
        // the unchecked version just skips the length equal check
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381G1Msm),
            None,
        )?;
        self.as_budget().bulk_charge(
            ContractCostType::InstantiateWasmDataSegmentBytes,
            points.len() as u64,
            Some(equivalent_instantiate_wasm_data_segment_bytes(ExperimentalCostType::Bls12381G1Msm)),
        )?;
        Ok(G1Projective::msm_unchecked(points, scalars))
    }

    pub(crate) fn map_fp_to_g1_internal(&self, fp: Fq) -> Result<G1Affine, HostError> {
        // TODO: metering, we lump the cost of `new` and `map_to_curve` into a single cost
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381MapFpToG1),
            None,
        )?;
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

    pub(crate) fn hash_to_g1_internal<T: AsRef<[u8]>>(
        &self,
        msg: T,
    ) -> Result<G1Affine, HostError> {
        // TODO: metering
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381HashToG1),
            None,
        )?;
        let g1_mapper = MapToCurveBasedHasher::<
            Projective<g1::Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<g1::Config>,
        >::new(BLS12381_G1_DST.as_bytes())
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

    pub(crate) fn g2_vec_from_vecobj(&self, vp: VecObject) -> Result<Vec<G2Affine>, HostError> {
        let len: u32 = self.vec_len(vp)?.into();
        // TODO: metering charge memalloc
        let mut points: Vec<G2Affine> = vec![];
        points.reserve(len as usize);
        let _ = self.visit_obj(vp, |vp: &HostVec| {
            for p in vp.iter() {
                let pp =
                    self.g2_affine_deserialize_from_bytesobj(BytesObject::try_from_val(self, p)?)?;
                points.push(pp);
            }
            Ok(())
        });
        Ok(points)
    }

    pub(crate) fn g2_add_internal(
        &self,
        p0: G2Affine,
        p1: G2Affine,
    ) -> Result<G2Projective, HostError> {
        // TODO: metering
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381G2Add),
            None,
        )?;
        Ok(p0.add(p1))
    }

    pub(crate) fn g2_mul_internal(
        &self,
        p0: G2Affine,
        scalar: Fr,
    ) -> Result<G2Projective, HostError> {
        // TODO: metering
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381G2Mul),
            None,
        )?;
        Ok(p0.mul(scalar))
    }

    pub(crate) fn g2_msm_internal(
        &self,
        points: &[G2Affine],
        scalars: &[Fr],
    ) -> Result<G2Projective, HostError> {
        // TODO: metering msm
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381G2Msm),
            None,
        )?;
        self.as_budget().bulk_charge(
            ContractCostType::InstantiateWasmDataSegmentBytes,
            points.len() as u64,
            Some(equivalent_instantiate_wasm_data_segment_bytes(ExperimentalCostType::Bls12381G2Msm)),
        )?;
        Ok(G2Projective::msm_unchecked(points, scalars))
    }

    pub(crate) fn map_fp2_to_g2_internal(&self, fp: Fq2) -> Result<G2Affine, HostError> {
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381MapFp2ToG2),
            None,
        )?;
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

    pub(crate) fn hash_to_g2_internal<T: AsRef<[u8]>>(
        &self,
        msg: T,
    ) -> Result<G2Affine, HostError> {
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381HashToG2),
            None,
        )?;
        let mapper = MapToCurveBasedHasher::<
            Projective<g2::Config>,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<g2::Config>,
        >::new(BLS12381_G2_DST.as_bytes())
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
        vp1: Vec<G1Affine>,
        vp2: Vec<G2Affine>,
    ) -> Result<PairingOutput<Bls12_381>, HostError> {
        // TODO: metering. we lump these two steps into one cost type
        self.as_budget().bulk_charge(
            ContractCostType::WasmInsnExec,
            equivalent_wasm_insns(ExperimentalCostType::Bls12381Pairing),
            None,
        )?;
        self.as_budget().bulk_charge(
            ContractCostType::InstantiateWasmDataSegmentBytes,
            vp1.len() as u64,
            Some(equivalent_instantiate_wasm_data_segment_bytes(ExperimentalCostType::Bls12381Pairing)),
        )?;        
        let mlo = Bls12_381::multi_miller_loop(vp1, vp2);
        Bls12_381::final_exponentiation(mlo).ok_or_else(|| {
            self.err(
                ScErrorType::Crypto,
                ScErrorCode::InternalError,
                "fail to perform final exponentiation",
                &[],
            )
        })
    }

    pub(crate) fn check_pairing_output(
        &self,
        output: &PairingOutput<Bls12_381>,
    ) -> Result<Bool, HostError> {
        self.charge_budget(ContractCostType::MemCmp, Some(576))?;
        match output.0.cmp(&Fq12::ONE) {
            Ordering::Equal => Ok(true.into()),
            _ => Ok(false.into()),
        }
    }
    
    pub(crate) fn scalar_add_internal(&self, lhs: &mut Fr, rhs: &Fr) -> Result<(), HostError> {
        //TODO: metering
        lhs.add_assign(rhs);        
        Ok(())
    }

    pub(crate) fn scalar_sub_internal(&self, lhs: &mut Fr, rhs: &Fr) -> Result<(), HostError> {
        //TODO: metering
        lhs.sub_assign(rhs);        
        Ok(())
    }

    pub(crate) fn scalar_mul_internal(&self, lhs: &mut Fr, rhs: &Fr) -> Result<(), HostError> {
        //TODO: metering
        lhs.mul_assign(rhs);        
        Ok(())
    }

    pub(crate) fn scalar_pow_internal(&self, lhs: &Fr, rhs: &[u64]) -> Result<Fr, HostError> {
        // TODO: metering
        Ok(lhs.pow(rhs))
    }

    pub(crate) fn scalar_inv_internal(&self, lhs: &Fr) -> Result<Fr, HostError> {
        //TODO: metering
        // we bubble up this condition check to be extra safe, and provide a better error
        if lhs.is_zero() {
            return Err(self.err(ScErrorType::Crypto, ScErrorCode::InvalidInput, "scalar inversion input is zero", &[]));
        }
        lhs.inverse().ok_or_else(|| self.err(ScErrorType::Crypto, ScErrorCode::InternalError,format!("scalar inversion {} failed", lhs).as_str(), &[]))
    }
}
