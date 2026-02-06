//! Arena allocator performance benchmark
//!
//! This benchmark runs the COMPLEX contract to measure overall Host performance.
//! Run before and after each arena migration stage:
//!
//! ```bash
//! cargo bench --features bench -p soroban-env-host --bench arena_benchmark -- --nocapture
//! ```

use soroban_env_common::{Env, EnvBase, Symbol, VecObject};
use soroban_env_host::{
    budget::{AsBudget, Budget},
    storage::{Footprint, Storage},
    testutils::{generate_account_id, generate_bytes_array},
    Host, HostError, LedgerInfo, MeteredOrdMap,
};
use soroban_test_wasms::COMPLEX;
use std::time::Instant;

const LEDGER_INFO: LedgerInfo = LedgerInfo {
    protocol_version: soroban_env_host::meta::INTERFACE_VERSION.protocol,
    sequence_number: 1234,
    timestamp: 1234,
    network_id: [7; 32],
    base_reserve: 1,
    min_persistent_entry_ttl: 4096,
    min_temp_entry_ttl: 16,
    max_entry_ttl: 6312000,
};

const ITERATIONS: u32 = 10;

/// Create an empty args vector
fn empty_args(host: &Host) -> Result<VecObject, HostError> {
    host.vec_new_from_slice(&[])
}

fn benchmark_complex_contract() -> Result<(), HostError> {
    println!("=== Arena Performance Benchmark ===");
    println!("Running COMPLEX contract {} times\n", ITERATIONS);

    let mut times_us: Vec<u128> = Vec::with_capacity(ITERATIONS as usize);
    let mut cpu_insns_list: Vec<u64> = Vec::with_capacity(ITERATIONS as usize);
    let mut mem_bytes_list: Vec<u64> = Vec::with_capacity(ITERATIONS as usize);
    let mut arena_bytes_list: Vec<usize> = Vec::with_capacity(ITERATIONS as usize);

    for i in 0..ITERATIONS {
        // Run 1: record footprint (emulating preflight)
        let host = Host::test_host_with_recording_footprint();
        let account_id = generate_account_id(&host);
        let salt = generate_bytes_array(&host);

        host.set_ledger_info(LEDGER_INFO.clone())?;
        let contract_id_obj = host.register_test_contract_wasm_from_source_account(
            COMPLEX,
            account_id.clone(),
            salt,
        )?;
        host.call(
            contract_id_obj,
            Symbol::try_from_small_str("go")?,
            empty_args(&host)?,
        )?;
        let (store, _) = host.try_finish().unwrap();
        let foot = store.footprint;

        // Run 2: enforce footprint with measurement
        let store = Storage::with_enforcing_footprint_and_map(
            Footprint::default(),
            MeteredOrdMap::default(),
        );
        let host = Host::with_storage_and_budget(store, Budget::default());
        host.set_ledger_info(LEDGER_INFO)?;
        host.setup_storage_footprint(foot)?;
        let contract_id_obj =
            host.register_test_contract_wasm_from_source_account(COMPLEX, account_id, salt)?;

        // Reset budget before measurement
        host.as_budget().reset_unlimited()?;

        let start = Instant::now();
        host.call(
            contract_id_obj,
            Symbol::try_from_small_str("go")?,
            empty_args(&host)?,
        )?;
        let elapsed = start.elapsed();

        let budget = host.budget_cloned();
        let cpu_insns = budget.get_cpu_insns_consumed().unwrap();
        let mem_bytes = budget.get_mem_bytes_consumed().unwrap();
        let arena_bytes = host.arena_allocated_bytes();

        times_us.push(elapsed.as_micros());
        cpu_insns_list.push(cpu_insns);
        mem_bytes_list.push(mem_bytes);
        arena_bytes_list.push(arena_bytes);

        println!(
            "Run {:>2}: time={:>6}us, cpu={:>10}, mem={:>10}, arena={:>10}",
            i + 1,
            elapsed.as_micros(),
            cpu_insns,
            mem_bytes,
            arena_bytes
        );
    }

    // Compute statistics
    let total_time_us: u128 = times_us.iter().sum();
    let total_cpu_insns: u64 = cpu_insns_list.iter().sum();
    let total_mem_bytes: u64 = mem_bytes_list.iter().sum();
    let total_arena_bytes: usize = arena_bytes_list.iter().sum();

    let avg_time_us = total_time_us / ITERATIONS as u128;
    let avg_cpu_insns = total_cpu_insns / ITERATIONS as u64;
    let avg_mem_bytes = total_mem_bytes / ITERATIONS as u64;
    let avg_arena_bytes = total_arena_bytes / ITERATIONS as usize;

    let min_time_us = *times_us.iter().min().unwrap();
    let max_time_us = *times_us.iter().max().unwrap();

    println!("\n=== Results ===");
    println!("Iterations:      {}", ITERATIONS);
    println!("Avg time:        {} us", avg_time_us);
    println!("Min time:        {} us", min_time_us);
    println!("Max time:        {} us", max_time_us);
    println!("Avg CPU insns:   {}", avg_cpu_insns);
    println!("Avg mem bytes:   {}", avg_mem_bytes);
    println!("Avg arena bytes: {}", avg_arena_bytes);
    println!("Total time:      {} ms", total_time_us / 1_000);

    Ok(())
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn main() {
    benchmark_complex_contract().unwrap();
}
