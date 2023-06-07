// Run this with
// $ cargo bench --features wasmi,testutils --bench worst_case_linear_models -- --nocapture
// You can optionally pass in args listing the {`ContractCostType`, `WasmInsnType`} combination to run with, e.g.
// $ cargo bench --features wasmi,testutils --bench worst_case_linear_models -- VecNew I64Rotr --nocapture
mod common;
use crate::MemTracker;
use common::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use soroban_env_host::{budget::AsBudget, Host, Vm};
use std::{
    default,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tracking_allocator::{AllocationGroupToken, AllocationRegistry, AllocationTracker, Allocator};

#[derive(Default, Debug)]
struct stats {
    pub engine: Vec<u64>,
    pub module: Vec<u64>,
    pub store: Vec<u64>,
    pub linker: Vec<u64>,
    pub pre_instance: Vec<u64>,
    pub instance: Vec<u64>,
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn main() -> std::io::Result<()> {
    env_logger::init();
    use std::time::Instant;
    println!("hello");
    let host = Host::default();
    host.as_budget().reset_unlimited();
    let mut rng = StdRng::from_seed([0xff; 32]);

    let inputs = 1..10;
    let mut stats = stats::default();

    for input in inputs {
        let code = VmInstantiationMeasure::new_worst_case(&host, &mut rng, input).wasm;

        let mut cpu_insn_counter = cpu::InstructionCounter::new();
        let mem_tracker = MemTracker(Arc::new(AtomicU64::new(0)));
        AllocationRegistry::set_global_tracker(mem_tracker.clone())
            .expect("no other global tracker should be set yet");
        AllocationRegistry::enable_tracking();
        let mut alloc_group_token =
            AllocationGroupToken::register().expect("failed to register allocation group");

        // start the cpu and mem measurement
        mem_tracker.0.store(0, Ordering::SeqCst);
        let alloc_guard = alloc_group_token.enter();
        let start = Instant::now();
        cpu_insn_counter.begin();

        let engine = Vm::engine(host.as_budget());
        // println!("engine {}", cpu_insn_counter.check_and_count());
        stats.engine.push(cpu_insn_counter.check_and_count());
        let module = Vm::module(&host, &engine, code.as_ref())?;
        // println!("module {}", cpu_insn_counter.check_and_count());
        stats.module.push(cpu_insn_counter.check_and_count());
        let mut store = Vm::store(&engine, &host);
        // println!("store {}", cpu_insn_counter.check_and_count());
        stats.store.push(cpu_insn_counter.check_and_count());
        let linker = Vm::linker(&host, &engine, &mut store)?;
        // println!("linker {}", cpu_insn_counter.check_and_count());
        stats.linker.push(cpu_insn_counter.check_and_count());
        let not_started_instance = Vm::instance_pre(&host, &linker, &mut store, &module)?;
        // println!("pre-instance {}", cpu_insn_counter.check_and_count());
        stats.pre_instance.push(cpu_insn_counter.check_and_count());
        let instance = Vm::instance(&host, not_started_instance, &mut store)?;
        // println!("instance {}", cpu_insn_counter.check_and_count());
        stats.instance.push(cpu_insn_counter.check_and_count());

        // collect the metrics
        // let cpu_insns = cpu_insn_counter.end_and_count();
        let stop = Instant::now();
        drop(alloc_guard);

        AllocationRegistry::disable_tracking();
        unsafe {
            AllocationRegistry::clear_global_tracker();
        }
    }
    println!("stats: {:?}", stats);

    Ok(())
}
