mod bls12_381;
mod decode_secp256r1_sig;
mod ecdsa_secp256k1_verify;
mod ecdsa_secp256r1_recover;
mod ed25519_scalar_mut;
mod read_xdr;
mod sec1_decode_point_compressed;

pub use bls12_381::*;
pub use decode_secp256r1_sig::*;
pub use ecdsa_secp256k1_verify::*;
pub use ecdsa_secp256r1_recover::*;
pub use ed25519_scalar_mut::*;
pub use read_xdr::*;
pub use sec1_decode_point_compressed::*;

use crate::xdr::Name;
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExperimentalCostType {
    EdwardsPointCurve25519ScalarMul,
    ReadXdrByteArray,
    EcdsaSecp256r1Recover,
    Sec1DecodePointCompressed,
    DecodeSecp256r1Signature,
    EcdsaSecp256k1Verify,
    Bls12381G1AffineDeserializeUncompressed,
    Bls12381G1AffineSerializeUncompressed,
    Bls12381G2AffineDeserializeUncompressed,
    Bls12381G2AffineSerializeUncompressed,
    Bls12381FpSerializeUncompressed,
    Bls12381FpDeserializeUncompressed,
    Bls12381Fp2DeserializeUncompressed,
    Bls12381Fp12SerializeUncompressed,
    Bls12381G1ProjectiveToAffine,
    Bls12381G2ProjectiveToAffine,
    Bls12381G1Add,
    Bls12381G1Mul,
    Bls12381G1Msm,
    Bls12381MapFpToG1,
    Bls12381HashToG1,
    Bls12381G2Add,
    Bls12381G2Mul,
    Bls12381G2Msm,
    Bls12381MapFp2ToG2,
    Bls12381HashToG2,
    Bls12381MillerLoop,
    Bls12381FinalExp,
    Bls12381Pairing,
}

impl Name for ExperimentalCostType {
    fn name(&self) -> &'static str {
        match self {
            ExperimentalCostType::EdwardsPointCurve25519ScalarMul => {
                "EdwardsPointCurve25519ScalarMul"
            }
            ExperimentalCostType::ReadXdrByteArray => "ReadXdrByteArray",
            ExperimentalCostType::EcdsaSecp256r1Recover => "EcdsaSecp256r1Recover",
            ExperimentalCostType::Sec1DecodePointCompressed => "Sec1DecodePointCompressed",
            ExperimentalCostType::DecodeSecp256r1Signature => "DecodeSecp256r1Signature",
            ExperimentalCostType::EcdsaSecp256k1Verify => "EcdsaSecp256k1Verify",
            ExperimentalCostType::Bls12381G1AffineDeserializeUncompressed => {
                "Bls12381G1AffineDeserializeUncompressed"
            }
            ExperimentalCostType::Bls12381G1AffineSerializeUncompressed => {
                "Bls12381G1AffineSerializeUncompressed"
            }
            ExperimentalCostType::Bls12381G2AffineDeserializeUncompressed => {
                "Bls12381G2AffineDeserializeUncompressed"
            }
            ExperimentalCostType::Bls12381G2AffineSerializeUncompressed => {
                "Bls12381G2AffineSerializeUncompressed"
            }
            ExperimentalCostType::Bls12381FpSerializeUncompressed => {
                "Bls12381FpSerializeUncompressed"
            }
            ExperimentalCostType::Bls12381FpDeserializeUncompressed => {
                "Bls12381FpDeserializeUncompressed"
            }
            ExperimentalCostType::Bls12381Fp2DeserializeUncompressed => {
                "Bls12381Fp2DeserializeUncompressed"
            }
            ExperimentalCostType::Bls12381Fp12SerializeUncompressed => {
                "Bls12381Fp12SerializeUncompressed"
            }
            ExperimentalCostType::Bls12381G1ProjectiveToAffine => "Bls12381G1ProjectiveToAffine",
            ExperimentalCostType::Bls12381G2ProjectiveToAffine => "Bls12381G2ProjectiveToAffine",
            ExperimentalCostType::Bls12381G1Add => "Bls12381G1Add",
            ExperimentalCostType::Bls12381G1Mul => "Bls12381G1Mul",
            ExperimentalCostType::Bls12381G1Msm => "Bls12381G1Msm",
            ExperimentalCostType::Bls12381MapFpToG1 => "Bls12381MapFpToG1",
            ExperimentalCostType::Bls12381HashToG1 => "Bls12381HashToG1",
            ExperimentalCostType::Bls12381G2Add => "Bls12381G2Add",
            ExperimentalCostType::Bls12381G2Mul => "Bls12381G2Mul",
            ExperimentalCostType::Bls12381G2Msm => "Bls12381G2Msm",
            ExperimentalCostType::Bls12381MapFp2ToG2 => "Bls12381MapFp2ToG2",
            ExperimentalCostType::Bls12381HashToG2 => "Bls12381HashToG2",
            ExperimentalCostType::Bls12381MillerLoop => "Bls12381MillerLoop",
            ExperimentalCostType::Bls12381FinalExp => "Bls12381FinalExp",
            ExperimentalCostType::Bls12381Pairing => "Bls12381Pairing",
        }
    }
}

impl fmt::Display for ExperimentalCostType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
