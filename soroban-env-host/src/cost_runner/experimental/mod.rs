mod ed25519_scalar_mut;
mod read_xdr;
mod vm_ops;

pub use ed25519_scalar_mut::*;
pub use read_xdr::*;
pub use vm_ops::*;

use crate::xdr::Name;
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExperimentalCostType {
    EdwardsPointCurve25519ScalarMul,
    ReadXdrByteArray,
    VmMemRead,
    VmMemWrite,
    ParseWasmModule,
    VmCachedInstantiation,
}

impl Name for ExperimentalCostType {
    fn name(&self) -> &'static str {
        match self {
            ExperimentalCostType::EdwardsPointCurve25519ScalarMul => {
                "EdwardsPointCurve25519ScalarMul"
            }
            ExperimentalCostType::ReadXdrByteArray => "ReadXdrByteArray",
            ExperimentalCostType::VmMemRead => "VmMemRead",
            ExperimentalCostType::VmMemWrite => "VmMemWrite",
            ExperimentalCostType::ParseWasmModule => "ParseWasmModule",
            ExperimentalCostType::VmCachedInstantiation => "VmCachedInstantiation",
        }
    }
}

impl fmt::Display for ExperimentalCostType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
