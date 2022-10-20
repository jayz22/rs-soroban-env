// Run this with
// $ cargo bench calibrate_host_ops -- --nocapture

mod common;

use common::*;
use crypto_bigint::{Random, U256, U8192};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
// use im_rc::Vector;
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::FromPrimitive;
use rand::SeedableRng;
use rand_chacha; // 0.3.0
                 // use rand_chacha::rand_core::SeedableRng;
                 // use rand_core::RngCore;
use sha2::{Digest, Sha256};
use soroban_env_host::{
    budget::CostType,
    xdr::{ScMap, ScMapEntry, ScObject, ScVal, ScVec},
    EnvVal, Host, RawVal,
};

const DIVIDEND: u64 = 71;

struct ScVecToHostVecRun {
    val: ScVal,
}

struct ImVecNewRun {
    count: u64,
    val: ScVal,
}

struct ScMapToHostMapRun {
    val: ScVal,
}

struct ImMapImmutEntryRun {
    map: im_rc::OrdMap<EnvVal<Host, RawVal>, EnvVal<Host, RawVal>>,
    size: u64,
}

struct ImMapMutEntryRun {
    map: im_rc::OrdMap<EnvVal<Host, RawVal>, EnvVal<Host, RawVal>>,
    size: u64,
}

struct ImVecImmutEntryRun {
    vec: im_rc::Vector<EnvVal<Host, RawVal>>,
    size: u64,
}

struct ImVecMutEntryRun {
    vec: im_rc::Vector<EnvVal<Host, RawVal>>,
    size: u64,
}

struct HostObjAllocSlotRun {
    count: u64,
    val: ScVal,
}

struct ComputeSha256HashRun {
    buf: Vec<u8>,
}

struct ComputeEd25519PubKeyRun {
    keys: Vec<Vec<u8>>,
}

struct VerifyEd25519SigRun {
    key: PublicKey,
    msg: Vec<u8>,
    sig: Signature,
}

struct BigIntDivRem {
    divisor: BigInt,
    dividend: BigInt,
}

struct CryptoU256DivRem {
    divisor: U256,
    dividend: U256,
}

struct CryptoU8192DivRem {
    divisor: U8192,
    dividend: U8192,
}

struct CryptoU256DivRemFixedDivisor {
    divisor: U256,
    dividend: U256,
}

/// Measures the costs of allocating vectors of varying sizes.
impl HostCostMeasurement for ScVecToHostVecRun {
    const COST_TYPE: CostType = CostType::ScVecToHostVec;

    fn new(_host: &Host, size_hint: u64) -> Self {
        let size = size_hint * 10000;
        let scvec: ScVec = ScVec(
            (0..size)
                .map(|i| ScVal::U32(i as u32))
                .collect::<Vec<ScVal>>()
                .try_into()
                .unwrap(),
        );
        let val = ScVal::Object(Some(ScObject::Vec(scvec)));
        Self { val }
    }

    fn run(&mut self, host: &Host) {
        host.inject_val(&self.val).unwrap();
    }
}

/// Measures the costs of allocating large numbers of 0-sized vectors.
impl HostCostMeasurement for ImVecNewRun {
    const COST_TYPE: CostType = CostType::ImVecNew;

    fn new(_host: &Host, size_hint: u64) -> Self {
        let size = size_hint * 1000;
        let scvec: ScVec = ScVec(vec![].try_into().unwrap());
        let val = ScVal::Object(Some(ScObject::Vec(scvec)));
        Self { count: size, val }
    }

    fn run(&mut self, host: &Host) {
        for _ in 0..self.count {
            host.inject_val(&self.val).unwrap();
        }
    }
}

/// Measures the costs of allocating maps of varying sizes.
impl HostCostMeasurement for ScMapToHostMapRun {
    const COST_TYPE: CostType = CostType::ScMapToHostMap;

    fn new(_host: &Host, size_hint: u64) -> Self {
        let size = size_hint * 10000;
        let scmap: ScMap = ScMap(
            (0..size)
                .map(|i| ScMapEntry {
                    key: ScVal::U32(i as u32),
                    val: ScVal::U32(i as u32),
                })
                .collect::<Vec<ScMapEntry>>()
                .try_into()
                .unwrap(),
        );
        let val = ScVal::Object(Some(ScObject::Map(scmap)));
        Self { val }
    }

    fn run(&mut self, host: &Host) {
        host.inject_val(&self.val).unwrap();
    }
}

/// Measures the costs of accessing maps of varying sizes.
impl HostCostMeasurement for ImMapImmutEntryRun {
    const COST_TYPE: CostType = CostType::ImMapImmutEntry;

    fn new(host: &Host, size_hint: u64) -> Self {
        let size = size_hint * 10000;
        let map: im_rc::OrdMap<EnvVal<Host, RawVal>, EnvVal<Host, RawVal>> = (0..size)
            .map(|k| {
                let ev = EnvVal {
                    env: host.clone(),
                    val: RawVal::from_u32(k as u32),
                };
                (ev.clone(), ev)
            })
            .collect();
        Self { map, size }
    }

    fn run(&mut self, host: &Host) {
        let ev = EnvVal {
            env: host.clone(),
            val: RawVal::from_u32((self.size / 2) as u32),
        };
        let _ = self.map.get(&ev);
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.size as u64
    }
}

impl HostCostMeasurement for ImMapMutEntryRun {
    const COST_TYPE: CostType = CostType::ImMapMutEntry;

    fn new(host: &Host, size_hint: u64) -> Self {
        let size = size_hint * 10000;
        let map: im_rc::OrdMap<EnvVal<Host, RawVal>, EnvVal<Host, RawVal>> = (0..size)
            .map(|k| {
                let ev = EnvVal {
                    env: host.clone(),
                    val: RawVal::from_u32(k as u32),
                };
                (ev.clone(), ev)
            })
            .collect();
        Self { map, size }
    }

    fn run(&mut self, host: &Host) {
        let ev = EnvVal {
            env: host.clone(),
            val: RawVal::from_u32((self.size / 2) as u32),
        };
        let _ = self.map.get_mut(&ev);
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.size as u64
    }
}

impl HostCostMeasurement for ImVecImmutEntryRun {
    const COST_TYPE: CostType = CostType::ImVecImmutEntry;

    fn new(host: &Host, size_hint: u64) -> Self {
        let size = size_hint * 1000;
        let vec: im_rc::Vector<EnvVal<Host, RawVal>> = (0..size)
            .map(|k| EnvVal {
                env: host.clone(),
                val: RawVal::from_u32(k as u32),
            })
            .collect();
        Self { vec, size }
    }

    fn run(&mut self, _host: &Host) {
        let _ = self.vec.get((self.size / 2) as usize);
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.size as u64
    }
}

impl HostCostMeasurement for ImVecMutEntryRun {
    const COST_TYPE: CostType = CostType::ImVecMutEntry;

    fn new(host: &Host, size_hint: u64) -> Self {
        let size = size_hint * 10000;
        let vec: im_rc::Vector<EnvVal<Host, RawVal>> = (0..size)
            .map(|k| EnvVal {
                env: host.clone(),
                val: RawVal::from_u32(k as u32),
            })
            .collect();
        Self { vec, size }
    }

    fn run(&mut self, _host: &Host) {
        let _ = self.vec.get_mut((self.size / 2) as usize);
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.size as u64
    }
}

/// Measures the costs of allocating large numbers of simple objects.
impl HostCostMeasurement for HostObjAllocSlotRun {
    const COST_TYPE: CostType = CostType::HostObjAllocSlot;

    fn new(_host: &Host, size_hint: u64) -> Self {
        let size = size_hint * 10000;
        let val = ScVal::Object(Some(ScObject::I64(0)));
        Self { count: size, val }
    }

    fn run(&mut self, host: &Host) {
        for _ in 0..self.count {
            host.inject_val(&self.val).unwrap();
        }
    }
}

impl HostCostMeasurement for ComputeSha256HashRun {
    const COST_TYPE: CostType = CostType::ComputeSha256Hash;

    fn new(_host: &Host, size_hint: u64) -> Self {
        let size = size_hint * 100;
        let buf: Vec<u8> = (0..size).map(|n| n as u8).collect();
        Self { buf }
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.buf.len() as u64
    }

    fn run(&mut self, _host: &Host) {
        Sha256::digest(&self.buf).as_slice().to_vec();
    }
}

impl HostCostMeasurement for ComputeEd25519PubKeyRun {
    const COST_TYPE: CostType = CostType::ComputeEd25519PubKey;

    fn new(_host: &Host, size_hint: u64) -> Self {
        let mut csprng = rand::rngs::StdRng::from_seed([0xff; 32]);
        let keys = (0..size_hint)
            .map(|_| {
                let secret = SecretKey::generate(&mut csprng);
                let public: PublicKey = (&secret).into();
                public.as_bytes().as_slice().into()
            })
            .collect();
        Self { keys }
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.keys.len() as u64
    }

    fn run(&mut self, _host: &Host) {
        for i in self.keys.iter() {
            ed25519_dalek::PublicKey::from_bytes(i.as_slice()).expect("publickey");
        }
    }
}

impl HostCostMeasurement for VerifyEd25519SigRun {
    const COST_TYPE: CostType = CostType::VerifyEd25519Sig;

    fn new(_host: &Host, size_hint: u64) -> Self {
        let size_hint = size_hint * 10000;
        let mut csprng = rand::rngs::StdRng::from_seed([0xff; 32]);
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let key: PublicKey = keypair.public.clone();
        let msg: Vec<u8> = (0..size_hint).map(|x| x as u8).collect();
        let sig: Signature = keypair.sign(msg.as_slice());
        Self { key, msg, sig }
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.msg.len() as u64
    }

    fn run(&mut self, _host: &Host) {
        self.key
            .verify(self.msg.as_slice(), &self.sig)
            .expect("verify")
    }
}

impl HostCostMeasurement for BigIntDivRem {
    const COST_TYPE: CostType = CostType::BigIntDivRem;

    fn new(_host: &Host, input_hint: u64) -> Self {
        let size_hint = input_hint;
        let buf = (0..size_hint).map(|i| i as u8).collect::<Vec<u8>>();
        let divisor = BigInt::from_bytes_le(Sign::Plus, buf.as_slice());
        Self {
            divisor,
            dividend: BigInt::from_u64(DIVIDEND).unwrap(),
        }
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.divisor.bits()
    }

    fn run(&mut self, _host: &Host) {
        self.divisor.div_rem(&self.dividend);
    }
}

impl HostCostMeasurement for CryptoU256DivRem {
    const COST_TYPE: CostType = CostType::BigIntDivRem;

    fn new(_host: &Host, input_hint: u64) -> Self {
        let size_hint = input_hint;
        let mut buf = (0..size_hint).map(|i| i as u8).collect::<Vec<u8>>();
        buf.resize(32, 0);
        let divisor = U256::from_le_slice(&buf);
        // use rand_chacha::rand_core::SeedableRng;
        // let rng = rand_chacha::ChaCha8Rng::seed_from_u64(10);
        // let divisor = U256::random(rng);
        // println!("{:?}", divisor);
        Self {
            divisor,
            dividend: U256::from_u64(DIVIDEND),
        }
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.divisor.clone().bits_vartime() as u64
    }

    fn run(&mut self, _host: &Host) {
        self.divisor.div_rem(&self.dividend);
    }
}

impl HostCostMeasurement for CryptoU8192DivRem {
    const COST_TYPE: CostType = CostType::BigIntDivRem;

    fn new(_host: &Host, input_hint: u64) -> Self {
        let size_hint = input_hint;
        // let size_hint = 10;
        let mut buf = (0..size_hint).map(|i| i as u8).collect::<Vec<u8>>();
        // println!("{:?}", buf);

        buf.resize(1024, 0);
        let divisor = U8192::from_le_slice(&buf);
        // println!("{:?}", divisor);
        Self {
            divisor,
            dividend: U8192::from_u64(2),
        }
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.divisor.clone().bits_vartime() as u64
    }

    fn run(&mut self, _host: &Host) {
        // for _ in 0..100 {
        //     self.divisor.div_rem(&self.dividend);
        // }
        self.divisor.div_rem(&self.dividend);
        // println!("{:?}", res);
    }
}

impl HostCostMeasurement for CryptoU256DivRemFixedDivisor {
    const COST_TYPE: CostType = CostType::BigIntDivRem;

    fn new(_host: &Host, input_hint: u64) -> Self {
        let size_hint = input_hint;
        let mut buf = (0..size_hint).map(|i| i as u8).collect::<Vec<u8>>();
        buf.resize(32, 0);
        let divisor =
            U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let dividend = U256::from_le_slice(&buf);
        Self { divisor, dividend }
    }

    fn get_input(&self, _host: &Host) -> u64 {
        self.dividend.clone().bits_vartime() as u64
    }

    fn run(&mut self, _host: &Host) {
        self.divisor.div_rem(&self.dividend);
    }
}

fn measure_one<M: HostCostMeasurement>() -> std::io::Result<()> {
    let mut measurements = measure_costs::<M>(0..33)?;
    // measurements.subtract_baseline();
    measurements.report();

    // if std::env::var("FIT_MODELS").is_ok() {
    //     measurements.fit_model_to_cpu();
    //     measurements.fit_model_to_mem();
    // }
    Ok(())
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn main() -> std::io::Result<()> {
    env_logger::init();
    // measure_one::<ScVecToHostVecRun>()?;
    // measure_one::<ScMapToHostMapRun>()?;
    // measure_one::<ImVecNewRun>()?;
    // measure_one::<ImMapImmutEntryRun>()?;
    // measure_one::<ImMapMutEntryRun>()?;
    // measure_one::<ImVecImmutEntryRun>()?;
    // measure_one::<ImVecMutEntryRun>()?;
    // measure_one::<HostObjAllocSlotRun>()?;
    // measure_one::<ComputeSha256HashRun>()?;
    // measure_one::<ComputeEd25519PubKeyRun>()?;
    // measure_one::<VerifyEd25519SigRun>()?;
    // measure_one::<BigIntDivRem>()?;
    // measure_one::<CryptoU256DivRem>()?;
    // measure_one::<CryptoU8192DivRem>()?;
    measure_one::<CryptoU256DivRemFixedDivisor>()?;
    Ok(())
}
