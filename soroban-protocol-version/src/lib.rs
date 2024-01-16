// If the "next" feature is enabled, we're building from the "next" xdr
// definitions branch and rust module, which contains experimental, unstable,
// in-development definitions we aren't even close to ready to release to the
// network. This is typically associated with a one-higher-than-released
// protocol number for testing purposes.
#[cfg(feature = "next")]
pub const LEDGER_PROTOCOL_VERSION: u32 = 21;
#[cfg(feature = "next")]
pub const PRE_RELEASE_VERSION: u32 = 1;

// If the "next" feature is _not_ enabled, it means we're building for a
// nearly-current release to the network and are using the "curr" xdr branch and
// module. This will therefore be associated with a current or nearly-current
// network protocol number.
#[cfg(not(feature = "next"))]
pub const LEDGER_PROTOCOL_VERSION: u32 = 20;
#[cfg(not(feature = "next"))]
pub const PRE_RELEASE_VERSION: u32 = 0;

pub const fn get_ledger_protocol_version(interface_version: u64) -> u32 {
    // The ledger protocol version is the high 32 bits of INTERFACE_VERSION
    (interface_version >> 32) as u32
}

pub const fn get_pre_release_version(interface_version: u64) -> u32 {
    // The pre-release version is the low 32 bits of INTERFACE_VERSION
    interface_version as u32
}
