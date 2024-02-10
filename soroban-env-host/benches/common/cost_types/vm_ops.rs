#[allow(unused)]
use super::wasm_insn_exec::{
    wasm_module_input_size_for_scale_factor, wasm_module_with_scale_factor,
};
use crate::common::{util, HostCostMeasurement};
use rand::{rngs::StdRng, Rng};
use soroban_env_host::{
    cost_runner::{VmInstantiationRun, VmInstantiationSample},
    xdr, Host,
};

pub(crate) struct VmInstantiationMeasure;

// This measures the cost of instantiating a host::Vm on a variety of possible
// wasm modules, of different sizes. The input value should be the size of the
// module, though for now we're just selecting modules from the fixed example
// repertoire. Costs should be linear.
impl HostCostMeasurement for VmInstantiationMeasure {
    type Runner = VmInstantiationRun;

    fn new_best_case(_host: &Host, _rng: &mut StdRng) -> VmInstantiationSample {
        let id: xdr::Hash = [0; 32].into();
        let wasm: Vec<u8> = soroban_test_wasms::ADD_I32.into();
        VmInstantiationSample { id: Some(id), wasm }
    }

    fn new_worst_case(_host: &Host, _rng: &mut StdRng, input: u64) -> VmInstantiationSample {
        let id: xdr::Hash = [0; 32].into();
        // which represents the worst case in terms of work needed for WASM parsing.
        // generate a test wasm contract with many trivial internal functions,
        let input = wasm_module_input_size_for_scale_factor(input);
        let wasm = wasm_module_with_scale_factor(input);
        VmInstantiationSample { id: Some(id), wasm }
    }

    fn new_random_case(_host: &Host, rng: &mut StdRng, _input: u64) -> VmInstantiationSample {
        let id: xdr::Hash = [0; 32].into();
        let idx = rng.gen_range(0..=10) % util::TEST_WASMS.len();
        let wasm = util::TEST_WASMS[idx].into();
        VmInstantiationSample { id: Some(id), wasm }
    }
}
