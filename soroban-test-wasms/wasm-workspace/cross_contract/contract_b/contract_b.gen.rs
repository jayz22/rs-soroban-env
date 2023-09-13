#![feature(prelude_import)]
#![no_std]
#[prelude_import]
use core::prelude::rust_2021::*;
#[macro_use]
extern crate core;
extern crate compiler_builtins as _;
use soroban_sdk::{contract, contractimpl, Address, Env};
mod contract_a {
    pub const WASM: &[u8] = b"\x00asm\x01\x00\x00\x00\x01\n\x02`\x02~~\x01~`\x00\x00\x03\x05\x04\x00\x01\x01\x01\x05\x03\x01\x00\x10\x06\x19\x03\x7f\x01A\x80\x80\xc0\x00\x0b\x7f\x00A\x80\x80\xc0\x00\x0b\x7f\x00A\x80\x80\xc0\x00\x0b\x07/\x05\x06memory\x02\x00\x03add\x00\x00\x01_\x00\x03\n__data_end\x03\x01\x0b__heap_base\x03\x02\n]\x04I\x01\x02\x7f\x02@\x02@ \x00B\xff\x01\x83B\x04R\r\x00 \x01B\xff\x01\x83B\x04R\r\x00 \x00B \x88\xa7\"\x02 \x01B \x88\xa7j\"\x03 \x02I\r\x01 \x03\xadB \x86B\x04\x84\x0f\x0b\x00\x00\x0b\x10\x81\x80\x80\x80\x00\x00\x0b\t\x00\x10\x82\x80\x80\x80\x00\x00\x0b\x04\x00\x00\x00\x0b\x02\x00\x0b\x00\x1e\x11contractenvmetav0\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x003\x00o\x0econtractmetav0\x00\x00\x00\x00\x00\x00\x00\x05rsver\x00\x00\x00\x00\x00\x00\x061.72.0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08rssdkver\x00\x00\x00.0.9.2#bfddbc380e2b23c71069bd612b89177400437a80\x00\x00\x00K\x0econtractspecv0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03add\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01x\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01y\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x04";
    pub trait Contract {
        fn add(env: soroban_sdk::Env, x: u32, y: u32) -> u32;
    }
    ///Client is a client for calling the contract defined in "Contract".
    pub struct Client<'a> {
        pub env: soroban_sdk::Env,
        pub address: soroban_sdk::Address,
        #[doc(hidden)]
        #[cfg(not(any(test, feature = "testutils")))]
        _phantom: core::marker::PhantomData<&'a ()>,
    }
    impl<'a> Client<'a> {
        pub fn new(env: &soroban_sdk::Env, address: &soroban_sdk::Address) -> Self {
            Self {
                env: env.clone(),
                address: address.clone(),
                #[cfg(not(any(test, feature = "testutils")))]
                _phantom: core::marker::PhantomData,
            }
        }
    }
    impl<'a> Client<'a> {
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
            Result<
                u32,
                <u32 as soroban_sdk::TryFromVal<soroban_sdk::Env, soroban_sdk::Val>>::Error,
            >,
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
}
pub struct ContractB;
///ContractBClient is a client for calling the contract defined in "ContractB".
pub struct ContractBClient<'a> {
    pub env: soroban_sdk::Env,
    pub address: soroban_sdk::Address,
    #[doc(hidden)]
    #[cfg(not(any(test, feature = "testutils")))]
    _phantom: core::marker::PhantomData<&'a ()>,
}
impl<'a> ContractBClient<'a> {
    pub fn new(env: &soroban_sdk::Env, address: &soroban_sdk::Address) -> Self {
        Self {
            env: env.clone(),
            address: address.clone(),
            #[cfg(not(any(test, feature = "testutils")))]
            _phantom: core::marker::PhantomData,
        }
    }
}
impl ContractB {
    pub fn add_with(env: Env, contract: Address, x: u32, y: u32) -> u32 {
        let client = contract_a::Client::new(&env, &contract);
        client.add(&x, &y)
    }
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub static __SPEC_XDR_FN_ADD_WITH: [u8; 84usize] = ContractB::spec_xdr_add_with();
impl ContractB {
    pub const fn spec_xdr_add_with() -> [u8; 84usize] {
        *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08add_with\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x08contract\x00\x00\x00\x13\x00\x00\x00\x00\x00\x00\x00\x01x\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01y\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x04"
    }
}
impl<'a> ContractBClient<'a> {
    pub fn add_with(&self, contract: &Address, x: &u32, y: &u32) -> u32 {
        use soroban_sdk::{FromVal, IntoVal};
        self.env.invoke_contract(
            &self.address,
            &soroban_sdk::Symbol::new(&self.env, &"add_with"),
            ::soroban_sdk::Vec::from_array(
                &self.env,
                [
                    contract.into_val(&self.env),
                    x.into_val(&self.env),
                    y.into_val(&self.env),
                ],
            ),
        )
    }
    pub fn try_add_with(
        &self,
        contract: &Address,
        x: &u32,
        y: &u32,
    ) -> Result<
        Result<u32, <u32 as soroban_sdk::TryFromVal<soroban_sdk::Env, soroban_sdk::Val>>::Error>,
        Result<soroban_sdk::Error, <soroban_sdk::Error as TryFrom<soroban_sdk::Error>>::Error>,
    > {
        use soroban_sdk::{FromVal, IntoVal};
        self.env.try_invoke_contract(
            &self.address,
            &soroban_sdk::Symbol::new(&self.env, &"add_with"),
            ::soroban_sdk::Vec::from_array(
                &self.env,
                [
                    contract.into_val(&self.env),
                    x.into_val(&self.env),
                    y.into_val(&self.env),
                ],
            ),
        )
    }
}
#[doc(hidden)]
pub mod __add_with {
    use super::*;
    #[deprecated(note = "use `ContractBClient::new(&env, &contract_id).add_with` instead")]
    pub extern "C" fn invoke_raw(
        env: soroban_sdk::Env,
        arg_0: soroban_sdk::Val,
        arg_1: soroban_sdk::Val,
        arg_2: soroban_sdk::Val,
    ) -> soroban_sdk::Val {
        <_ as soroban_sdk::IntoVal<
            soroban_sdk::Env,
            soroban_sdk::Val,
        >>::into_val(
            #[allow(deprecated)]
            &<super::ContractB>::add_with(
                env.clone(),
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
                <_ as soroban_sdk::unwrap::UnwrapOptimized>::unwrap_optimized(
                    <_ as soroban_sdk::TryFromVal<
                        soroban_sdk::Env,
                        soroban_sdk::Val,
                    >>::try_from_val(&env, &arg_2),
                ),
            ),
            &env,
        )
    }
    #[deprecated(note = "use `ContractBClient::new(&env, &contract_id).add_with` instead")]
    pub fn invoke_raw_slice(env: soroban_sdk::Env, args: &[soroban_sdk::Val]) -> soroban_sdk::Val {
        #[allow(deprecated)]
        invoke_raw(env, args[0usize], args[1usize], args[2usize])
    }
    use super::*;
}
