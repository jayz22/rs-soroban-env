// High-level design for Poseidon/Poseidon2 CryptographicSponge wrappers
//
// Key insight: Poseidon and Poseidon2 share the same sponge construction
// (absorb/squeeze operations) and only differ in their internal permutation
// functions. This design reflects that by:
//
// 1. Defining a PoseidonPermutation trait for the permutation operation
// 2. Implementing a generic PoseidonSponge<P> that works with any permutation
// 3. Providing wrappers for zkhash's Poseidon and Poseidon2 that implement
//    the PoseidonPermutation trait
//
// Architecture:
// - PoseidonPermutation trait: abstracts the permutation function
// - PoseidonSponge<P>: generic sponge using permutation P
// - PoseidonV1/PoseidonV2: wrappers around zkhash implementations
// - Both implement CryptographicSponge and FieldBasedCryptographicSponge

use std::sync::Arc;
use ark_ff::PrimeField;
use ark_crypto_primitives::sponge::{
    CryptographicSponge, FieldBasedCryptographicSponge,
    DuplexSpongeMode, Absorb, FieldElementSize
};
use zkhash::poseidon::poseidon::Poseidon as PoseidonImpl;
use zkhash::poseidon::poseidon_params::PoseidonParams;
use zkhash::poseidon2::poseidon2::Poseidon2 as Poseidon2Impl;
use zkhash::poseidon2::poseidon2_params::Poseidon2Params;

// ============================================================================
// Permutation Abstraction
// ============================================================================

/// Trait abstracting the Poseidon permutation function.
/// Both Poseidon and Poseidon2 implement this with different internal permutations.
pub trait PoseidonPermutation<F: PrimeField>: Clone {
    /// Configuration type for the permutation
    type Config;

    /// Create a new permutation with the given configuration
    fn new(config: &Self::Config) -> Self;

    /// Get the width of the permutation (t parameter: rate + capacity)
    fn width(&self) -> usize;

    /// Apply the permutation to a state of t field elements
    fn permute(&self, state: &[F]) -> Vec<F>;
}

// ============================================================================
// Poseidon V1 Permutation Wrapper
// ============================================================================

/// Wrapper around zkhash's Poseidon (v1) that implements PoseidonPermutation
#[derive(Clone)]
pub struct PoseidonV1<F: PrimeField> {
    inner: PoseidonImpl<F>,
}

impl<F: PrimeField> PoseidonPermutation<F> for PoseidonV1<F> {
    type Config = Arc<PoseidonParams<F>>;

    fn new(config: &Self::Config) -> Self {
        Self {
            inner: PoseidonImpl::new(config),
        }
    }

    fn width(&self) -> usize {
        self.inner.get_t()
    }

    fn permute(&self, state: &[F]) -> Vec<F> {
        self.inner.permutation(state)
    }
}

// ============================================================================
// Poseidon V2 Permutation Wrapper
// ============================================================================

/// Wrapper around zkhash's Poseidon2 that implements PoseidonPermutation
#[derive(Clone)]
pub struct PoseidonV2<F: PrimeField> {
    inner: Poseidon2Impl<F>,
}

impl<F: PrimeField> PoseidonPermutation<F> for PoseidonV2<F> {
    type Config = Arc<Poseidon2Params<F>>;

    fn new(config: &Self::Config) -> Self {
        Self {
            inner: Poseidon2Impl::new(config),
        }
    }

    fn width(&self) -> usize {
        self.inner.get_t()
    }

    fn permute(&self, state: &[F]) -> Vec<F> {
        self.inner.permutation(state)
    }
}

// ============================================================================
// Generic Sponge Construction
// ============================================================================

/// Generic sponge construction that works with any PoseidonPermutation.
/// This implements the standard duplex sponge construction shared by both
/// Poseidon and Poseidon2.
#[derive(Clone)]
pub struct PoseidonSponge<F: PrimeField, P: PoseidonPermutation<F>> {
    /// The underlying permutation (Poseidon v1 or v2)
    permutation: P,
    /// Current sponge state (t field elements where t = rate + capacity)
    state: Vec<F>,
    /// Duplex sponge mode (absorbing or squeezing)
    mode: DuplexSpongeMode,
    /// Rate parameter (number of elements absorbed/squeezed per permutation)
    rate: usize,
    /// Capacity parameter (t - rate, for security)
    capacity: usize,
}

impl<F: PrimeField, P: PoseidonPermutation<F>> PoseidonSponge<F, P> {
    pub fn new(config: &P::Config, rate: usize) -> Self {
        let permutation = P::new(&config);
        let t = permutation.width();
        let capacity = t - rate;

        assert!(rate > 0 && rate < t, "Rate must be between 0 and width");

        Self {
            permutation,
            state: vec![F::zero(); t],
            mode: DuplexSpongeMode::Absorbing { next_absorb_index: 0 },
            rate,
            capacity,
        }
    }

    pub fn absorb(&mut self, elems: Vec<F>) {
        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.parameters.rate {
                    self.permute();
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, elems.as_slice());
            }
            DuplexSpongeMode::Squeezing {
                next_squeeze_index: _,
            } => {
                self.absorb_internal(0, elems.as_slice());
            }
        };
    }

    pub fn squeeze_native_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        let mut squeezed_elems = vec![F::zero(); num_elements];
        match self.mode {
            DuplexSpongeMode::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute();
                self.squeeze_internal(0, &mut squeezed_elems);
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.parameters.rate {
                    self.permute();
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems);
            }
        };

        squeezed_elems
    }

    // Absorbs everything in elements, this does not end in an absorbtion.
    fn absorb_internal(&mut self, mut rate_start_index: usize, elements: &[F]) {
        let mut remaining_elements = elements;

        loop {
            // if we can finish in this call
            if rate_start_index + remaining_elements.len() <= self.parameters.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[self.parameters.capacity + i + rate_start_index] += element;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };

                return;
            }
            // otherwise absorb (rate - rate_start_index) elements
            let num_elements_absorbed = self.parameters.rate - rate_start_index;
            for (i, element) in remaining_elements
                .iter()
                .enumerate()
                .take(num_elements_absorbed)
            {
                self.state[self.parameters.capacity + i + rate_start_index] += element;
            }
            self.permute();
            // the input elements got truncated by num elements absorbed
            remaining_elements = &remaining_elements[num_elements_absorbed..];
            rate_start_index = 0;
        }
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    fn squeeze_internal(&mut self, mut rate_start_index: usize, output: &mut [F]) {
        let mut output_remaining = output;
        loop {
            // if we can finish in this call
            if rate_start_index + output_remaining.len() <= self.parameters.rate {
                output_remaining.clone_from_slice(
                    &self.state[self.parameters.capacity + rate_start_index
                        ..(self.parameters.capacity + output_remaining.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + output_remaining.len(),
                };
                return;
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.parameters.rate - rate_start_index;
            output_remaining[..num_elements_squeezed].clone_from_slice(
                &self.state[self.parameters.capacity + rate_start_index
                    ..(self.parameters.capacity + num_elements_squeezed + rate_start_index)],
            );

            // Repeat with updated output slices
            output_remaining = &mut output_remaining[num_elements_squeezed..];
            // Unless we are done with squeezing in this call, permute.
            if !output_remaining.is_empty() {
                self.permute();
            }

            rate_start_index = 0;
        }
    }    
}





/// Configuration for the sponge construction
pub struct PoseidonSpongeConfig<P> {
    /// Permutation configuration (params for Poseidon or Poseidon2)
    pub permutation_config: P,
    /// Rate parameter (must be < width)
    pub rate: usize,
}

impl<F: PrimeField, P: PoseidonPermutation<F>> PoseidonSponge<F, P> {
    /// Apply the permutation to the internal state
    fn apply_permutation(&mut self) {
        self.state = self.permutation.permute(&self.state);
    }

    /// Absorb field elements into the sponge state
    fn absorb_internal(&mut self, elements: &[F]) {
        // TODO: Implement duplex sponge absorbing logic
        // 1. Check/switch to Absorbing mode
        // 2. XOR/add elements into state at rate positions
        // 3. When rate positions are filled, call apply_permutation()
        // 4. Continue with remaining elements
    }

    /// Squeeze field elements from the sponge state
    fn squeeze_internal(&mut self, num_elements: usize) -> Vec<F> {
        // TODO: Implement duplex sponge squeezing logic
        // 1. If in Absorbing mode, call apply_permutation() and switch to Squeezing
        // 2. Extract elements from rate positions
        // 3. When rate is exhausted, call apply_permutation() for more
        // 4. Continue until num_elements are produced
        vec![]
    }
}




// ============================================================================
// CryptographicSponge Implementation (shared by both versions)
// ============================================================================

impl<F: PrimeField, P: PoseidonPermutation<F>> CryptographicSponge for PoseidonSponge<F, P> {
    type Config = PoseidonSpongeConfig<P::Config>;

    fn new(config: &Self::Config) -> Self {
        let permutation = P::new(&config.permutation_config);
        let t = permutation.width();
        let rate = config.rate;
        let capacity = t - rate;

        assert!(rate > 0 && rate < t, "Rate must be between 0 and width");

        Self {
            permutation,
            state: vec![F::zero(); t],
            mode: DuplexSpongeMode::Absorbing { next_absorb_index: 0 },
            rate,
            capacity,
        }
    }

    fn absorb(&mut self, input: &impl Absorb) {
        // TODO: Convert input to field elements using Absorb trait
        // and call absorb_internal
        // let elements = input.to_sponge_field_elements::<F>();
        // self.absorb_internal(&elements);
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        // TODO: Squeeze field elements and convert to bytes
        // 1. Calculate how many field elements needed for num_bytes
        // 2. Call squeeze_internal
        // 3. Convert field elements to bytes (little-endian)
        vec![]
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        // TODO: Squeeze field elements and convert to bits
        // 1. Calculate how many field elements needed for num_bits
        // 2. Call squeeze_internal
        // 3. Convert field elements to bits (little-endian)
        vec![]
    }
}

// ============================================================================
// FieldBasedCryptographicSponge Implementation (shared by both versions)
// ============================================================================

impl<F: PrimeField, P: PoseidonPermutation<F>> FieldBasedCryptographicSponge<F>
    for PoseidonSponge<F, P>
{
    fn squeeze_native_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        self.squeeze_internal(num_elements)
    }
}

// ============================================================================
// Type Aliases for Convenience
// ============================================================================

/// Poseidon sponge using the original Poseidon permutation
pub type Poseidon1Sponge<F> = PoseidonSponge<F, PoseidonV1<F>>;

/// Poseidon sponge using the Poseidon2 permutation
pub type Poseidon2Sponge<F> = PoseidonSponge<F, PoseidonV2<F>>;
