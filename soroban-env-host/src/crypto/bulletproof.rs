use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use std::sync::LazyLock;

use crate::{
    xdr::{ContractCostType, ScBytes, ScErrorCode, ScErrorType},
    BytesObject, Host, HostError, U32Val, VecObject,
};

// Max bitsize for range proofs
const RANGEPROOF_MAX_GENS_CAPACITY: usize = 64;
// Max aggregation capacity (number of range proofs in one verification)
const RANGEPROOF_MAX_PARTY_CAPACITY: usize = 16;
// Public parameters of the Bulletproof range proof system.
static BULLETPROOF_GENERATORS: LazyLock<BulletproofGens> = LazyLock::new(|| {
    BulletproofGens::new(RANGEPROOF_MAX_GENS_CAPACITY, RANGEPROOF_MAX_PARTY_CAPACITY)
});

pub(crate) fn range_proof_from_bytes(
    host: &Host,
    proof: BytesObject,
) -> Result<RangeProof, HostError> {
    host.visit_obj(proof, |bytes: &ScBytes| {
        // TODO: Add specific metering for bulletproof deserialization
        host.charge_budget(ContractCostType::MemCpy, Some(bytes.len() as u64))?;

        RangeProof::from_bytes(bytes.as_slice()).map_err(|_e| {
            host.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "invalid bulletproof range proof bytes",
                &[],
            )
        })
    })
}

pub(crate) fn commitments_from_vec_object(
    host: &Host,
    commitments: VecObject,
) -> Result<Vec<CompressedRistretto>, HostError> {
    host.visit_obj(commitments, |vec: &crate::host_object::HostVec| {
        // Validate number of commitments
        if vec.len() == 0 {
            return Err(host.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "at least one commitment required for verification",
                &[],
            ));
        }

        if vec.len() > RANGEPROOF_MAX_PARTY_CAPACITY {
            return Err(host.err(
                ScErrorType::Crypto,
                ScErrorCode::InvalidInput,
                "too many commitments for bulletproof verification",
                &[U32Val::from(vec.len() as u32).into()],
            ));
        }

        let mut result = Vec::with_capacity(vec.len());
        for val in vec.iter() {
            // Convert to BytesObject and process immediately
            let comm_obj = BytesObject::try_from(*val).map_err(|_| {
                host.err(
                    ScErrorType::Value,
                    ScErrorCode::UnexpectedType,
                    "expected BytesObject in commitments vector",
                    &[],
                )
            })?;

            let commitment = host.visit_obj(comm_obj, |bytes: &ScBytes| {
                // TODO: Add specific metering for commitment deserialization
                host.charge_budget(ContractCostType::MemCpy, Some(bytes.len() as u64))?;

                if bytes.len() != 32 {
                    return Err(host.err(
                        ScErrorType::Crypto,
                        ScErrorCode::InvalidInput,
                        "commitment must be exactly 32 bytes",
                        &[U32Val::from(bytes.len() as u32).into()],
                    ));
                }

                let mut commitment_bytes = [0u8; 32];
                commitment_bytes.copy_from_slice(bytes.as_slice());

                CompressedRistretto::from_slice(&commitment_bytes).map_err(|_| {
                    host.err(
                        ScErrorType::Crypto,
                        ScErrorCode::InvalidInput,
                        "invalid ristretto point for commitment",
                        &[],
                    )
                })
            })?;

            result.push(commitment);
        }
        Ok(result)
    })
}

pub(crate) fn bulletproof_verify_multiple_values_in_range(
    host: &Host,
    proof: &RangeProof,
    dst: &[u8],
    nbits: usize,
    value_commitments: &[CompressedRistretto],
) -> Result<(), HostError> {
    // TODO: Add specific metering for bulletproof verification
    // For now, charge based on number of commitments and bit size
    host.charge_budget(
        ContractCostType::MemCpy,
        Some((value_commitments.len() * nbits) as u64),
    )?;

    // We use the default Ristretto basepoint and hash-to-basepoint as the base
    // points for the Pedersen commitment.
    let pc_gens = PedersenGens::default();

    host.with_current_prng(|prng| {
        // Use the provided domain separation tag for bulletproof verification
        let mut transcript = Transcript::new(dst);

        proof
            .verify_multiple_with_rng(
                &BULLETPROOF_GENERATORS,
                &pc_gens,
                &mut transcript,
                value_commitments,
                nbits,
                prng,
            )
            .map_err(|_e| {
                host.err(
                    ScErrorType::Crypto,
                    ScErrorCode::InvalidInput,
                    "bulletproof verification failed",
                    &[],
                )
            })
    })
}
