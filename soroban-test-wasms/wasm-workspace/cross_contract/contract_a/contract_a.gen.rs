#![feature(prelude_import)]
#![no_std]
#[prelude_import]
use core::prelude::rust_2021::*;
#[macro_use]
extern crate core;
extern crate compiler_builtins as _;
use soroban_sdk::{contract, contractimpl};
pub struct ContractA;
///ContractAClient is a client for calling the contract defined in "ContractA".
pub struct ContractAClient<'a> {
    pub env: soroban_sdk::Env,
    pub address: soroban_sdk::Address,
    #[doc(hidden)]
    #[cfg(not(any(test, feature = "testutils")))]
    _phantom: core::marker::PhantomData<&'a ()>,
}
impl<'a> ContractAClient<'a> {
    pub fn new(env: &soroban_sdk::Env, address: &soroban_sdk::Address) -> Self {
        Self {
            env: env.clone(),
            address: address.clone(),
            #[cfg(not(any(test, feature = "testutils")))]
            _phantom: core::marker::PhantomData,
        }
    }
}
impl ContractA {
    pub fn add(x: u32, y: u32) -> u32 {
        x.checked_add(y).expect("no overflow")
    }
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub static __SPEC_XDR_FN_ADD: [u8; 60usize] = ContractA::spec_xdr_add();
impl ContractA {
    pub const fn spec_xdr_add() -> [u8; 60usize] {
        *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03add\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01x\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01y\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x04"
    }
}
impl<'a> ContractAClient<'a> {
    pub fn add(&self, x: &u32, y: &u32) -> u32 {
        use soroban_sdk::{FromVal, IntoVal};
        self.env.invoke_contract(
            &self.address,
            &soroban_sdk::Symbol::new(&self.env, &"add"),
            ::soroban_sdk::Vec::from_array(
                &self.env,
                [x.into_val(&self.env), y.into_val(&self.env)],
            ),
        )
    }
    pub fn try_add(
        &self,
        x: &u32,
        y: &u32,
    ) -> Result<
        Result<u32, <u32 as soroban_sdk::TryFromVal<soroban_sdk::Env, soroban_sdk::Val>>::Error>,
        Result<soroban_sdk::Error, <soroban_sdk::Error as TryFrom<soroban_sdk::Error>>::Error>,
    > {
        use soroban_sdk::{FromVal, IntoVal};
        self.env.try_invoke_contract(
            &self.address,
            &soroban_sdk::Symbol::new(&self.env, &"add"),
            ::soroban_sdk::Vec::from_array(
                &self.env,
                [x.into_val(&self.env), y.into_val(&self.env)],
            ),
        )
    }
}
#[doc(hidden)]
pub mod __add {
    use super::*;
    #[deprecated(note = "use `ContractAClient::new(&env, &contract_id).add` instead")]
    pub extern "C" fn invoke_raw(
        env: soroban_sdk::Env,
        arg_0: soroban_sdk::Val,
        arg_1: soroban_sdk::Val,
    ) -> soroban_sdk::Val {
        <_ as soroban_sdk::IntoVal<
            soroban_sdk::Env,
            soroban_sdk::Val,
        >>::into_val(
            #[allow(deprecated)]
            &<super::ContractA>::add(
                <_ as soroban_sdk::unwrap::UnwrapOptimized>::unwrap_optimized(
                    <_ as soroban_sdk::TryFromVal<
                        soroban_sdk::Env,
                        soroban_sdk::Val,
                    >>::try_from_val(&env, &arg_0),
                ),
                <_ as soroban_sdk::unwrap::UnwrapOptimized>::unwrap_optimized(
                    <_ as soroban_sdk::TryFromVal<
                        soroban_sdk::Env,
                        soroban_sdk::Val,
                    >>::try_from_val(&env, &arg_1),
                ),
            ),
            &env,
        )
    }
    #[deprecated(note = "use `ContractAClient::new(&env, &contract_id).add` instead")]
    pub fn invoke_raw_slice(env: soroban_sdk::Env, args: &[soroban_sdk::Val]) -> soroban_sdk::Val {
        #[allow(deprecated)]
        invoke_raw(env, args[0usize], args[1usize])
    }
    use super::*;
}
