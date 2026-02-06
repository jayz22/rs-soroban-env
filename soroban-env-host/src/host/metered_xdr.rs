use crate::{
    budget::Budget,
    crypto::sha256_hash_from_bytes_raw,
    xdr::{ContractCostType, Limited, ReadXdr, ScBytes, ScErrorCode, ScErrorType, WriteXdr},
    BytesObject, Host, HostError, DEFAULT_XDR_RW_LIMITS,
};
use bumpalo::collections::Vec as BumpVec;
use std::io::Write;

use super::ErrorHandler;

struct MeteredWrite<'a, W: Write> {
    budget: &'a Budget,
    w: &'a mut W,
}

impl<W> Write for MeteredWrite<'_, W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.budget
            .charge(ContractCostType::ValSer, Some(buf.len() as u64))
            .map_err(Into::<std::io::Error>::into)?;
        self.w.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

impl Host {
    pub fn metered_hash_xdr(&self, obj: &impl WriteXdr) -> Result<[u8; 32], HostError> {
        let _span = tracy_span!("hash xdr");
        let mut buf = vec![];
        metered_write_xdr(self.budget_ref(), obj, &mut buf)?;
        sha256_hash_from_bytes_raw(&buf, self)
    }

    /// Hash XDR using the frame arena for the temporary buffer.
    /// This avoids global allocator overhead for the temporary buffer.
    /// Falls back to standard allocation if no frame is active.
    #[allow(dead_code)]
    pub(crate) fn metered_hash_xdr_arena(&self, obj: &impl WriteXdr) -> Result<[u8; 32], HostError> {
        let _span = tracy_span!("hash xdr arena");

        // Try to use frame arena if available
        let result = self.with_frame_arena(|arena| {
            let mut buf: BumpVec<u8> = BumpVec::new_in(arena);
            metered_write_xdr_arena(self.budget_ref(), obj, &mut buf)?;
            sha256_hash_from_bytes_raw(buf.as_slice(), self)
        });

        // Fall back to standard allocation if no frame is active
        match result {
            Ok(hash) => Ok(hash),
            Err(_) => self.metered_hash_xdr(obj),
        }
    }

    pub fn metered_from_xdr<T: ReadXdr>(&self, bytes: &[u8]) -> Result<T, HostError> {
        let _span = tracy_span!("read xdr");
        self.charge_budget(ContractCostType::ValDeser, Some(bytes.len() as u64))?;
        let mut limits = DEFAULT_XDR_RW_LIMITS;
        limits.len = bytes.len();
        self.map_err(T::from_xdr(bytes, limits))
    }

    pub(crate) fn metered_from_xdr_obj<T: ReadXdr>(
        &self,
        bytes: BytesObject,
    ) -> Result<T, HostError> {
        self.visit_obj(bytes, |hv: &ScBytes| self.metered_from_xdr(hv.as_slice()))
    }
}

pub fn metered_write_xdr(
    budget: &Budget,
    obj: &impl WriteXdr,
    w: &mut Vec<u8>,
) -> Result<(), HostError> {
    let _span = tracy_span!("write xdr");
    let mut w = Limited::new(MeteredWrite { budget, w }, DEFAULT_XDR_RW_LIMITS);
    // MeteredWrite above turned any budget failure into an IO error; we turn it
    // back to a budget failure here, since there's really no "IO error" that can
    // occur when writing to a Vec<u8>.
    obj.write_xdr(&mut w)
        .map_err(|_| (ScErrorType::Budget, ScErrorCode::ExceededLimit).into())
}

/// Write XDR to an arena-allocated buffer.
/// This is identical to `metered_write_xdr` but uses `BumpVec<u8>` instead of `Vec<u8>`.
#[allow(dead_code)]
pub(crate) fn metered_write_xdr_arena<'bump>(
    budget: &Budget,
    obj: &impl WriteXdr,
    w: &mut BumpVec<'bump, u8>,
) -> Result<(), HostError> {
    let _span = tracy_span!("write xdr arena");
    let mut w = Limited::new(MeteredWrite { budget, w }, DEFAULT_XDR_RW_LIMITS);
    obj.write_xdr(&mut w)
        .map_err(|_| (ScErrorType::Budget, ScErrorCode::ExceededLimit).into())
}

// Host-less metered XDR decoding.
// Prefer using `metered_from_xdr` when host is available for better error
// reporting.
pub fn metered_from_xdr_with_budget<T: ReadXdr>(
    bytes: &[u8],
    budget: &Budget,
) -> Result<T, HostError> {
    let _span = tracy_span!("read xdr with budget");
    budget.charge(ContractCostType::ValDeser, Some(bytes.len() as u64))?;
    let mut limits = DEFAULT_XDR_RW_LIMITS;
    limits.len = bytes.len();
    T::from_xdr(bytes, limits).map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::{ContractId, Hash as XdrHash, ScAddress, ScVal};
    use crate::{ContractFunctionSet, Symbol, Val};
    use std::rc::Rc;

    struct NoopContractFunctionSet;
    impl ContractFunctionSet for NoopContractFunctionSet {
        fn call(&self, _func: &Symbol, _host: &Host, _args: &[Val]) -> Option<Val> {
            Some(().into())
        }
    }

    #[test]
    fn test_arena_xdr_hashing() {
        // Create a Host with recording footprint
        let host = Host::test_host_with_recording_footprint();

        // Create an XDR value to hash
        let val = ScVal::I64(12345);

        // Hash using standard allocation (no frame)
        let hash_std = host.metered_hash_xdr(&val).unwrap();

        // Set up a test contract so we have a frame
        let id = [0u8; 32];
        let address = host
            .add_host_object(ScAddress::Contract(ContractId(XdrHash(id))))
            .unwrap();
        host.register_test_contract(address, Rc::new(NoopContractFunctionSet))
            .unwrap();

        // Hash using arena allocation (within a frame)
        let hash_arena = host
            .with_test_contract_frame(
                ContractId(XdrHash(id)),
                Symbol::try_from_small_str("test").unwrap(),
                || {
                    let result = host.metered_hash_xdr_arena(&val)?;
                    // Convert to Val for return, but we'll check the hash separately
                    assert_eq!(result, hash_std);
                    Ok(().into())
                },
            )
            .unwrap();

        // The with_test_contract_frame returns Val, but we already asserted inside
        let _ = hash_arena;
    }

    #[test]
    fn test_arena_fallback_without_frame() {
        // Create a Host without a frame
        let host = Host::test_host();

        let val = ScVal::I64(12345);

        // Without a frame, metered_hash_xdr_arena should fall back to standard allocation
        let hash = host.metered_hash_xdr_arena(&val).unwrap();
        let hash_std = host.metered_hash_xdr(&val).unwrap();

        assert_eq!(hash, hash_std);
    }
}
