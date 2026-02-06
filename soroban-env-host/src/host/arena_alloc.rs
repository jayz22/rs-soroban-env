#![allow(dead_code)]
//! Arena allocation helpers for soroban-env-host
//!
//! This module provides utilities for allocating data from the Host's arena allocator.
//! Arena allocation is faster than global allocation and provides better cache locality.
//!
//! # Usage Patterns
//!
//! ## Temporary Allocations
//! Use `alloc_slice` for temporary byte slices that are only needed during a single operation:
//! ```ignore
//! let data = host.arena_alloc_slice(&input_bytes)?;
//! // Process data...
//! // Memory is freed when the Host is dropped
//! ```
//!
//! ## Frame-Local Allocations
//! Use the frame arena for allocations that should be freed when the current frame exits:
//! ```ignore
//! let temp = host.frame_arena_alloc_slice(&data)?;
//! // temp is valid until the current frame is popped
//! ```

use bumpalo::Bump;

/// Extension trait for arena allocation from a Bump allocator
pub trait ArenaAlloc {
    /// Allocate a slice of bytes in the arena
    fn alloc_bytes(&self, data: &[u8]) -> &[u8];

    /// Allocate a slice of values in the arena
    fn alloc_slice<T: Clone>(&self, data: &[T]) -> &[T];

    /// Allocate a single value in the arena
    fn alloc_val<T>(&self, val: T) -> &T;

    /// Get the total allocated bytes in the arena
    fn allocated_bytes(&self) -> usize;
}

impl ArenaAlloc for Bump {
    fn alloc_bytes(&self, data: &[u8]) -> &[u8] {
        let slice = self.alloc_slice_copy(data);
        slice
    }

    fn alloc_slice<T: Clone>(&self, data: &[T]) -> &[T] {
        let slice = self.alloc_slice_clone(data);
        slice
    }

    fn alloc_val<T>(&self, val: T) -> &T {
        self.alloc(val)
    }

    fn allocated_bytes(&self) -> usize {
        Bump::allocated_bytes(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_alloc_bytes() {
        let bump = Bump::new();
        let data = b"hello world";
        let allocated = bump.alloc_bytes(data);
        assert_eq!(allocated, data);
        assert!(bump.allocated_bytes() > 0);
    }

    #[test]
    fn test_arena_alloc_slice() {
        let bump = Bump::new();
        let data = vec![1u32, 2, 3, 4, 5];
        let allocated = bump.alloc_slice(&data);
        assert_eq!(allocated, &data[..]);
        assert!(bump.allocated_bytes() > 0);
    }

    #[test]
    fn test_arena_alloc_val() {
        let bump = Bump::new();
        let val = 42u64;
        let allocated = bump.alloc_val(val);
        assert_eq!(*allocated, 42);
    }
}
