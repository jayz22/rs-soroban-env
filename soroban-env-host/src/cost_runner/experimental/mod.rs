mod ecdsa_decode_signature;
mod ecdsa_secp256r1_recover;
mod ecdsa_secp256r1_verify;
mod ed25519_scalar_mut;
mod read_xdr;
mod sec1_decode_point;

pub use ecdsa_decode_signature::*;
pub use ecdsa_secp256r1_recover::*;
pub use ecdsa_secp256r1_verify::*;
pub use ed25519_scalar_mut::*;
pub use read_xdr::*;
pub use sec1_decode_point::*;

use crate::xdr::Name;
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExperimentalCostType {
    EdwardsPointCurve25519ScalarMul,
    ReadXdrByteArray,
    EcdsaSecp256r1Verify,
    EcdsaSecp256r1Recover,
    Sec1DecodePointCompressed,
    Sec1DecodePointUncompressed,
    DecodeSecp256r1Signature,
    DecodeSecp256k1Signature,
}

impl Name for ExperimentalCostType {
    fn name(&self) -> &'static str {
        match self {
            ExperimentalCostType::EdwardsPointCurve25519ScalarMul => {
                "EdwardsPointCurve25519ScalarMul"
            }
            ExperimentalCostType::ReadXdrByteArray => "ReadXdrByteArray",
            ExperimentalCostType::EcdsaSecp256r1Verify => "EcdsaSecp256r1Verify",
            ExperimentalCostType::EcdsaSecp256r1Recover => "EcdsaSecp256r1Recover",
            ExperimentalCostType::Sec1DecodePointCompressed => "Sec1DecodePointCompressed",
            ExperimentalCostType::Sec1DecodePointUncompressed => "Sec1DecodePointUncompressed",
            ExperimentalCostType::DecodeSecp256r1Signature => "DecodeSecp256r1Signature",
            ExperimentalCostType::DecodeSecp256k1Signature => "DecodeSecp256k1Signature",
        }
    }
}

impl fmt::Display for ExperimentalCostType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
