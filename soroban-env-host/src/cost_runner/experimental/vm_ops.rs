use crate::{
    budget::CostTracker,
    cost_runner::{CostRunner, CostType, ExperimentalCostType},
    Vm,
};
use std::{hint::black_box, rc::Rc};

#[derive(Clone)]
pub struct VmMemRunSample {
    pub vm: Rc<Vm>,
    pub buf: Vec<u8>,
}

pub struct VmMemReadRun;
impl CostRunner for VmMemReadRun {
    const COST_TYPE: CostType = CostType::Experimental(ExperimentalCostType::VmMemRead);

    type SampleType = VmMemRunSample;

    type RecycledType = Self::SampleType;

    fn run_iter(
        host: &crate::Host,
        _iter: u64,
        mut sample: Self::SampleType,
    ) -> Self::RecycledType {
        black_box(
            sample
                .vm
                .with_vmcaller(|caller| {
                    host.metered_vm_read_bytes_from_linear_memory(
                        caller,
                        &sample.vm,
                        0,
                        &mut sample.buf,
                    )
                })
                .unwrap(),
        );
        sample
    }

    fn run_baseline_iter(
        _host: &crate::Host,
        _iter: u64,
        sample: Self::SampleType,
    ) -> Self::RecycledType {
        black_box(sample)
    }

    fn get_tracker(_host: &crate::Host, samples: &Vec<VmMemRunSample>) -> CostTracker {
        CostTracker {
            iterations: Self::RUN_ITERATIONS,
            inputs: Some(samples.iter().map(|x| x.buf.len() as u64).sum::<u64>()),
            cpu: 0,
            mem: 0,
        }
    }
}

pub struct VmMemWriteRun;
impl CostRunner for VmMemWriteRun {
    const COST_TYPE: CostType = CostType::Experimental(ExperimentalCostType::VmMemWrite);

    type SampleType = VmMemRunSample;

    type RecycledType = Self::SampleType;

    fn run_iter(
        host: &crate::Host,
        _iter: u64,
        mut sample: Self::SampleType,
    ) -> Self::RecycledType {
        black_box(
            sample
                .vm
                .with_vmcaller(|caller| {
                    host.metered_vm_write_bytes_to_linear_memory(
                        caller,
                        &sample.vm,
                        0,
                        &mut sample.buf,
                    )
                })
                .unwrap(),
        );
        sample
    }

    fn run_baseline_iter(
        _host: &crate::Host,
        _iter: u64,
        sample: Self::SampleType,
    ) -> Self::RecycledType {
        black_box(sample)
    }

    fn get_tracker(_host: &crate::Host, samples: &Vec<VmMemRunSample>) -> CostTracker {
        CostTracker {
            iterations: Self::RUN_ITERATIONS,
            inputs: Some(samples.iter().map(|x| x.buf.len() as u64).sum::<u64>()),
            cpu: 0,
            mem: 0,
        }
    }
}

#[derive(Clone)]
pub struct ParseModuleSample {
    pub input: u64,
    pub engine: wasmi::Engine,
    pub wasm: Vec<u8>,
    pub module: Option<Rc<wasmi::Module>>,
}

pub struct ParseWasmModuleRun;
impl CostRunner for ParseWasmModuleRun {
    const COST_TYPE: CostType = CostType::Experimental(ExperimentalCostType::ParseWasmModule);

    type SampleType = ParseModuleSample;

    const RUN_ITERATIONS: u64 = 100;

    type RecycledType = ParseModuleSample;

    fn run_baseline_iter(
        _host: &crate::Host,
        _iter: u64,
        sample: Self::SampleType,
    ) -> Self::RecycledType {
        sample
    }

    fn run_iter(
        _host: &crate::Host,
        _iter: u64,
        mut sample: Self::SampleType,
    ) -> Self::RecycledType {
        if let Ok(module) = wasmi::Module::new(&mut sample.engine, sample.wasm.as_slice()) {
            sample.module = Some(Rc::new(module));
        }
        sample
    }

    fn get_tracker(_host: &crate::Host, samples: &Vec<ParseModuleSample>) -> CostTracker {
        CostTracker {
            iterations: Self::RUN_ITERATIONS,
            inputs: Some(samples.iter().map(|x| x.input).sum::<u64>()),
            cpu: 0,
            mem: 0,
        }
    }
}

#[derive(Clone)]
pub struct VmCachedInstantiationSample {
    pub input: u64,
    // These are persistent across iterations
    pub engine: wasmi::Engine,
    pub linker: Rc<wasmi::Linker<()>>,
    pub wasm: Vec<u8>,
    pub module: Rc<wasmi::Module>,
    // These two will be created once per iteration
    pub store: Option<Rc<wasmi::Store<()>>>,
    pub instance: Option<Rc<wasmi::Instance>>,
}

pub struct VmCachedInstantiationRun;
impl CostRunner for VmCachedInstantiationRun {
    const COST_TYPE: CostType = CostType::Experimental(ExperimentalCostType::VmCachedInstantiation);

    type SampleType = VmCachedInstantiationSample;

    const RUN_ITERATIONS: u64 = 100;

    type RecycledType = VmCachedInstantiationSample;

    fn run_baseline_iter(
        _host: &crate::Host,
        _iter: u64,
        sample: Self::SampleType,
    ) -> Self::RecycledType {
        sample
    }

    fn run_iter(
        _host: &crate::Host,
        _iter: u64,
        mut sample: Self::SampleType,
    ) -> Self::RecycledType {
        let mut store = wasmi::Store::new(&sample.engine, ());
        if let Ok(ip) = sample.linker.instantiate(&mut store, &sample.module) {
            sample.instance = Some(Rc::new(ip.ensure_no_start(&mut store).unwrap()));
            sample.store = Some(Rc::new(store));
        }
        sample
    }

    fn get_tracker(_host: &crate::Host, samples: &Vec<VmCachedInstantiationSample>) -> CostTracker {
        CostTracker {
            iterations: Self::RUN_ITERATIONS,
            inputs: Some(samples.iter().map(|x| x.input).sum::<u64>()),
            cpu: 0,
            mem: 0,
        }
    }
}
