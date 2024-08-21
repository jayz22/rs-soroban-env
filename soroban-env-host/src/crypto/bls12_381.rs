use crate::host_object::HostVec;
use crate::{
    budget::AsBudget,
    xdr::{ContractCostType, ScBytes, ScErrorCode, ScErrorType},
    BytesObject, Host, HostError, Val, Bool
};
use ark_bls12_381::{g1, g2, Fq, Fq12, Fq2, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::short_weierstrass::Projective;
use ark_ec::CurveGroup;
use ark_ff::Field;
use sha2::Sha256;
use std::cmp::Ordering;
use std::ops::{Add, Mul};

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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use soroban_env_common::{Env, TryFromVal, U256Object, U256Small, U256Val, VecObject, U256};

const G1_SERIALIZED_SIZE: usize = 48;
const G2_SERIALIZED_SIZE: usize = 96;
// Domain Separation Tags specified according to https://datatracker.ietf.org/doc/rfc9380/
// section 3.1, 8.8
pub const BLS12381_G1_DST: &'static str = "Soroban-V00-CS00-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
pub const BLS12381_G2_DST: &'static str = "Soroban-V00-CS00-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

//========================================================================
// Some preliminary calibration results
//========================================================================
// | Cost Type                     |      CPU |   equivalent wasm insns  |
// |:------------------------------|---------:|-------------------------:|
// | Bls12381G1ProjectiveToAffine  |    88023 |                   22006  |
// | Bls12381G1Add                 |     7281 |                    1821  |
// | Bls12381G1Mul                 |  2277752 |                  569438  |
// | Bls12381G1Msm                 |  7237111 |                 1809278  |
// | Bls12381MapFpToG1             |  1510142 |                  377536  |
// | Bls12381HashToG1              |  3192885 |                  798222  |
// | Bls12381G2ProjectiveToAffine  |    95994 |                   24000  |
// | Bls12381G2Add                 |    23570 |                    5893  |
// | Bls12381G2Mul                 |  7075352 |                 1768838  |
// | Bls12381G2Msm                 | 10681052 |                 2670263  |
// | Bls12381MapFp2ToG2            |  2367368 |                  591842  |
// | Bls12381HashToG2              |  6870057 |                 1717515  |
// | Bls12381Pairing               | 14442475 |                 3610619  |
//========================================================================

enum ExperimentalCostType {
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
        ExperimentalCostType::Bls12381G1ProjectiveToAffine => 22006,
        ExperimentalCostType::Bls12381G1Add => 1821,
        ExperimentalCostType::Bls12381G1Mul => 569438,
        ExperimentalCostType::Bls12381G1Msm => 1809278,
        ExperimentalCostType::Bls12381MapFpToG1 => 377536,
        ExperimentalCostType::Bls12381HashToG1 => 798222,
        ExperimentalCostType::Bls12381G2ProjectiveToAffine => 24000,
        ExperimentalCostType::Bls12381G2Add => 5893,
        ExperimentalCostType::Bls12381G2Mul => 1768838,
        ExperimentalCostType::Bls12381G2Msm => 2670263,
        ExperimentalCostType::Bls12381MapFp2ToG2 => 591842,
        ExperimentalCostType::Bls12381HashToG2 => 1717515,
        ExperimentalCostType::Bls12381Pairing => 3610619,
    }
}

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
        self.serialize_into_bytesobj(g2, 2 * G2_SERIALIZED_SIZE, "G2 affine")
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
            self.visit_obj(obj, |u: &U256|  {
                Ok(Fr::from_le_bytes_mod_order(&u.to_le_bytes()))
            })?
        };
        Ok(fr)
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

    pub(crate) fn check_pairing_output(&self, output: &PairingOutput<Bls12_381>) -> Result<Bool, HostError> {
        self.charge_budget(ContractCostType::MemCmp, Some(576))?;
        match output.0.cmp(&Fq12::ONE) {
            Ordering::Equal => Ok(true.into()),
            _ => Ok(false.into()),
        }
    }
}
