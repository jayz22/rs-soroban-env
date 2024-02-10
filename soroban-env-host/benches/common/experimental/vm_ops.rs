use std::rc::Rc;

#[allow(unused)]
use crate::common::{
    wasm_module_input_size_for_scale_factor, wasm_module_with_scale_factor, HostCostMeasurement,
};
use rand::{rngs::StdRng, RngCore};
use soroban_env_host::{
    budget::CostTracker,
    cost_runner::{
        CostRunner, ParseModuleSample, ParseWasmModuleRun, VmCachedInstantiationRun,
        VmCachedInstantiationSample, VmMemReadRun, VmMemRunSample, VmMemWriteRun,
    },
    xdr, Host, Vm,
};

// Measures the cost of reading a slice of VM linear memory into a buffer.
// Input is bytes to read. CPU and memory cost should both be linear.
// TODO: does this run grow memory if the input exceeds 64kB?
pub(crate) struct VmMemReadMeasure;
impl HostCostMeasurement for VmMemReadMeasure {
    type Runner = VmMemReadRun;

    fn new_random_case(host: &Host, _rng: &mut StdRng, input: u64) -> VmMemRunSample {
        let input = 1 + input * Self::STEP_SIZE;
        let buf = vec![0; input as usize];
        let id: xdr::Hash = [0; 32].into();
        let code = soroban_test_wasms::ADD_I32;
        let vm = Vm::new(&host, id, &code).unwrap();
        VmMemRunSample { vm, buf }
    }
}

// Measures the cost of writing into a slice of VM linear memory.
// Input is bytes to write. CPU and memory cost should both be linear.
// TODO: does this run grow memory if the input exceeds 64kB?
pub(crate) struct VmMemWriteMeasure;
impl HostCostMeasurement for VmMemWriteMeasure {
    type Runner = VmMemWriteRun;

    fn new_random_case(host: &Host, rng: &mut StdRng, input: u64) -> VmMemRunSample {
        let input = 1 + input * Self::STEP_SIZE;
        let mut buf = vec![0; input as usize];
        rng.fill_bytes(buf.as_mut_slice());
        let id: xdr::Hash = [0; 32].into();
        let code = soroban_test_wasms::ADD_I32;
        let vm = Vm::new(&host, id, &code).unwrap();
        VmMemRunSample { vm, buf }
    }
}

fn new_engine() -> wasmi::Engine {
    let mut config = wasmi::Config::default();
    let cmode = match std::env::var("WASMI_COMPILATION_MODE")
        .unwrap_or("eager".to_string())
        .as_str()
    {
        "eager" => wasmi::CompilationMode::Eager,
        "lazy" => wasmi::CompilationMode::Lazy,
        "lazytranslation" => wasmi::CompilationMode::LazyTranslation,
        _ => panic!("Invalid WASMI_COMPILATION_MODE"),
    };
    config
        .wasm_multi_value(false)
        .wasm_mutable_global(true)
        .wasm_saturating_float_to_int(false)
        .wasm_sign_extension(true)
        .floats(false)
        .consume_fuel(true)
        .fuel_consumption_mode(wasmi::FuelConsumptionMode::Eager)
        .compilation_mode(cmode);
    wasmi::Engine::new(&config)
}

// Measures the cost of parsing a wasm module
pub(crate) struct ParseWasmModuleMeasure;
impl HostCostMeasurement for ParseWasmModuleMeasure {
    type Runner = ParseWasmModuleRun;

    fn new_random_case(_host: &Host, _rng: &mut StdRng, input: u64) -> ParseModuleSample {
        let input = wasm_module_input_size_for_scale_factor(input);
        let wasm = wasm_module_with_scale_factor(input);
        let engine = new_engine();
        ParseModuleSample {
            input,
            wasm,
            engine,
            module: None,
        }
    }

    fn get_tracker(
        _host: &Host,
        samples: &Vec<<Self::Runner as CostRunner>::RecycledType>,
    ) -> soroban_env_host::budget::CostTracker {
        CostTracker {
            iterations: <Self::Runner as CostRunner>::RUN_ITERATIONS,
            inputs: Some(samples.iter().map(|x| x.input).sum::<u64>()),
            cpu: 0,
            mem: 0,
        }
    }
}

pub(crate) struct VmCachedInstantiationMeasure;

// This measures the cost of instantiating a host::Vm with a cached module.
impl HostCostMeasurement for VmCachedInstantiationMeasure {
    type Runner = VmCachedInstantiationRun;

    fn new_random_case(_host: &Host, _rng: &mut StdRng, input: u64) -> VmCachedInstantiationSample {
        let mut engine = new_engine();
        let linker = Rc::new(<wasmi::Linker<()>>::new(&engine));

        let input = wasm_module_input_size_for_scale_factor(input);
        let wasm = wasm_module_with_scale_factor(input);
        let module = Rc::new(wasmi::Module::new(&mut engine, wasm.as_slice()).unwrap());

        VmCachedInstantiationSample {
            input,
            engine,
            linker,
            wasm,
            module,
            store: None,
            instance: None,
        }
    }
    fn get_tracker(
        _host: &Host,
        samples: &Vec<<Self::Runner as CostRunner>::RecycledType>,
    ) -> soroban_env_host::budget::CostTracker {
        CostTracker {
            iterations: <Self::Runner as CostRunner>::RUN_ITERATIONS,
            inputs: Some(samples.iter().map(|x| x.input).sum::<u64>()),
            cpu: 0,
            mem: 0,
        }
    }
}
