//! Microbenchmark comparing standard allocator vs arena allocator
//!
//! Run: cargo bench --features bench -p soroban-env-host --bench arena_microbench -- --nocapture

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

fn main() {
    println!("=== Arena Allocation Microbenchmark ===");
    println!("Iterations: {}", ITERATIONS);
    println!("Sizes: {:?}", SIZES);

    bench_std_vec();
    bench_std_vec_reuse();

    // Note: After Stage 1, arena benchmarks will be added here.
    // Currently this establishes baseline for standard allocation patterns.
    println!("\n(Bumpalo benchmark will be added after Stage 1)");
}
