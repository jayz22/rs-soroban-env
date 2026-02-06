//! Microbenchmark comparing standard allocator vs arena allocator
//!
//! Run: cargo bench --features bench -p soroban-env-host --bench arena_microbench -- --nocapture

use bumpalo::Bump;
use std::time::Instant;

const ITERATIONS: usize = 10_000;
const SIZES: [usize; 5] = [16, 64, 256, 1024, 4096];

fn bench_std_vec() {
    println!("\n=== Standard Vec Allocation ===");
    for &size in &SIZES {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let v: Vec<u8> = vec![0u8; size];
            std::hint::black_box(v);
        }
        let elapsed = start.elapsed();
        println!(
            "Size {:>5}: {:>8} ns/alloc",
            size,
            elapsed.as_nanos() / ITERATIONS as u128
        );
    }
}

fn bench_std_vec_reuse() {
    println!("\n=== Standard Vec with Reuse (clear + extend) ===");
    for &size in &SIZES {
        let mut v: Vec<u8> = Vec::with_capacity(size);
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            v.clear();
            v.extend(std::iter::repeat(0u8).take(size));
            std::hint::black_box(&v);
        }
        let elapsed = start.elapsed();
        println!(
            "Size {:>5}: {:>8} ns/iter",
            size,
            elapsed.as_nanos() / ITERATIONS as u128
        );
    }
}

fn bench_bumpalo_slice() {
    println!("\n=== Bumpalo Arena Allocation (slice) ===");
    for &size in &SIZES {
        // Create a fresh arena for each size test
        let bump = Bump::with_capacity(ITERATIONS * size);
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let slice: &mut [u8] = bump.alloc_slice_fill_default(size);
            std::hint::black_box(slice);
        }
        let elapsed = start.elapsed();
        println!(
            "Size {:>5}: {:>8} ns/alloc",
            size,
            elapsed.as_nanos() / ITERATIONS as u128
        );
    }
}

fn bench_bumpalo_vec() {
    println!("\n=== Bumpalo Arena Vec Allocation ===");
    for &size in &SIZES {
        use bumpalo::collections::Vec as BumpVec;
        // Create a fresh arena for each size test
        let bump = Bump::with_capacity(ITERATIONS * size);
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let mut v: BumpVec<u8> = BumpVec::with_capacity_in(size, &bump);
            v.extend(std::iter::repeat(0u8).take(size));
            std::hint::black_box(&v);
        }
        let elapsed = start.elapsed();
        println!(
            "Size {:>5}: {:>8} ns/alloc",
            size,
            elapsed.as_nanos() / ITERATIONS as u128
        );
    }
}

fn bench_bumpalo_reset() {
    println!("\n=== Bumpalo Arena with Reset (simulating per-invocation) ===");
    for &size in &SIZES {
        let mut bump = Bump::with_capacity(size * 10);
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let slice: &mut [u8] = bump.alloc_slice_fill_default(size);
            std::hint::black_box(slice);
            // Reset the arena - this is what happens between invocations
            bump.reset();
        }
        let elapsed = start.elapsed();
        println!(
            "Size {:>5}: {:>8} ns/alloc+reset",
            size,
            elapsed.as_nanos() / ITERATIONS as u128
        );
    }
}

fn bench_bumpalo_zeroed() {
    println!("\n=== Bumpalo Arena with alloc_slice_fill_copy ===");
    for &size in &SIZES {
        let bump = Bump::with_capacity(ITERATIONS * size);
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let slice: &mut [u8] = bump.alloc_slice_fill_copy(size, 0u8);
            std::hint::black_box(slice);
        }
        let elapsed = start.elapsed();
        println!(
            "Size {:>5}: {:>8} ns/alloc",
            size,
            elapsed.as_nanos() / ITERATIONS as u128
        );
    }
}

fn bench_many_small_allocs() {
    println!("\n=== Many Small Allocations (50 x 64 bytes per iteration) ===");
    const ALLOCS_PER_ITER: usize = 50;
    const SMALL_SIZE: usize = 64;

    // Standard allocation
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for _ in 0..ALLOCS_PER_ITER {
            let v: Vec<u8> = vec![0u8; SMALL_SIZE];
            std::hint::black_box(v);
        }
    }
    let elapsed_std = start.elapsed();

    // Arena allocation
    let bump = Bump::with_capacity(ITERATIONS * ALLOCS_PER_ITER * SMALL_SIZE);
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for _ in 0..ALLOCS_PER_ITER {
            let slice: &mut [u8] = bump.alloc_slice_fill_copy(SMALL_SIZE, 0u8);
            std::hint::black_box(slice);
        }
    }
    let elapsed_arena = start.elapsed();

    // Arena with reset per "invocation"
    let mut bump = Bump::with_capacity(ALLOCS_PER_ITER * SMALL_SIZE * 10);
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        for _ in 0..ALLOCS_PER_ITER {
            let slice: &mut [u8] = bump.alloc_slice_fill_copy(SMALL_SIZE, 0u8);
            std::hint::black_box(slice);
        }
        bump.reset();
    }
    let elapsed_arena_reset = start.elapsed();

    println!("Standard Vec:        {:>8} ns/iter", elapsed_std.as_nanos() / ITERATIONS as u128);
    println!("Arena (cumulative):  {:>8} ns/iter", elapsed_arena.as_nanos() / ITERATIONS as u128);
    println!("Arena (with reset):  {:>8} ns/iter", elapsed_arena_reset.as_nanos() / ITERATIONS as u128);
}

fn main() {
    println!("=== Arena Allocation Microbenchmark ===");
    println!("Iterations: {}", ITERATIONS);
    println!("Sizes: {:?}", SIZES);

    bench_std_vec();
    bench_std_vec_reuse();
    bench_bumpalo_slice();
    bench_bumpalo_vec();
    bench_bumpalo_reset();
    bench_bumpalo_zeroed();
    bench_many_small_allocs();

    println!("\n=== Summary ===");
    println!("Arena allocation benefits:");
    println!("1. Fast bump-pointer allocation (no free list traversal)");
    println!("2. Bulk deallocation via reset() - O(1) to free all memory");
    println!("3. Better cache locality for sequential allocations");
    println!("\nArena allocation is most beneficial when:");
    println!("- Making many small allocations in a short time");
    println!("- All allocations can be freed together");
    println!("- Memory fragmentation would otherwise be a concern");
}
