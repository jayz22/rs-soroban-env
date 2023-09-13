#![feature(prelude_import)]
#![no_std]
#[prelude_import]
use core::prelude::rust_2021::*;
#[macro_use]
extern crate core;
extern crate compiler_builtins as _;
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Env, Symbol, I256};
pub struct State {
    pub count: I256,
    pub last_exp: u32,
}
pub static __SPEC_XDR_TYPE_STATE: [u8; 68usize] = State::spec_xdr();
impl State {
    pub const fn spec_xdr() -> [u8; 68usize] {
        *b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05State\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x05count\x00\x00\x00\x00\x00\x00\r\x00\x00\x00\x00\x00\x00\x00\x08last_exp\x00\x00\x00\x04"
    }
}
impl soroban_sdk::TryFromVal<soroban_sdk::Env, soroban_sdk::Val> for State {
    type Error = soroban_sdk::ConversionError;
    fn try_from_val(
        env: &soroban_sdk::Env,
        val: &soroban_sdk::Val,
    ) -> Result<Self, soroban_sdk::ConversionError> {
        use soroban_sdk::{ConversionError, EnvBase, MapObject, TryIntoVal, Val};
        const KEYS: [&'static str; 2usize] = ["count", "last_exp"];
        let mut vals: [Val; 2usize] = [Val::VOID.to_val(); 2usize];
        let map: MapObject = val.try_into().map_err(|_| ConversionError)?;
        env.map_unpack_to_slice(map, &KEYS, &mut vals)
            .map_err(|_| ConversionError)?;
        Ok(Self {
            count: vals[0]
                .try_into_val(env)
                .map_err(|_| soroban_sdk::ConversionError)?,
            last_exp: vals[1]
                .try_into_val(env)
                .map_err(|_| soroban_sdk::ConversionError)?,
        })
    }
}
impl soroban_sdk::TryFromVal<soroban_sdk::Env, State> for soroban_sdk::Val {
    type Error = soroban_sdk::ConversionError;
    fn try_from_val(
        env: &soroban_sdk::Env,
        val: &State,
    ) -> Result<Self, soroban_sdk::ConversionError> {
        use soroban_sdk::{ConversionError, EnvBase, TryIntoVal, Val};
        const KEYS: [&'static str; 2usize] = ["count", "last_exp"];
        let vals: [Val; 2usize] = [
            (&val.count)
                .try_into_val(env)
                .map_err(|_| ConversionError)?,
            (&val.last_exp)
                .try_into_val(env)
                .map_err(|_| ConversionError)?,
        ];
        Ok(env
            .map_new_from_slices(&KEYS, &vals)
            .map_err(|_| ConversionError)?
            .into())
    }
}
const STATE: Symbol = {
    #[allow(deprecated)]
    const SYMBOL: soroban_sdk::Symbol = soroban_sdk::Symbol::short("STATE");
    SYMBOL
};
pub struct PowerContract;
///PowerContractClient is a client for calling the contract defined in "PowerContract".
pub struct PowerContractClient<'a> {
    pub env: soroban_sdk::Env,
    pub address: soroban_sdk::Address,
    #[doc(hidden)]
    #[cfg(not(any(test, feature = "testutils")))]
    _phantom: core::marker::PhantomData<&'a ()>,
}
impl<'a> PowerContractClient<'a> {
    pub fn new(env: &soroban_sdk::Env, address: &soroban_sdk::Address) -> Self {
        Self {
            env: env.clone(),
            address: address.clone(),
            #[cfg(not(any(test, feature = "testutils")))]
            _phantom: core::marker::PhantomData,
        }
    }
}
impl PowerContract {
    pub fn power(env: Env, exp: u32) -> I256 {
        let mut state: State = env.storage().instance().get(&STATE).unwrap();
        state.count = state.count.pow(exp);
        state.last_exp = exp;
        env.storage().instance().set(&STATE, &state);
        state.count
    }
}
#[doc(hidden)]
#[allow(non_snake_case)]
pub static __SPEC_XDR_FN_POWER: [u8; 48usize] = PowerContract::spec_xdr_power();
impl PowerContract {
    pub const fn spec_xdr_power() -> [u8; 48usize] {
        *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05power\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03exp\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\r"
    }
}
impl<'a> PowerContractClient<'a> {
    pub fn power(&self, exp: &u32) -> I256 {
        use soroban_sdk::{FromVal, IntoVal};
        self.env.invoke_contract(
            &self.address,
            &soroban_sdk::Symbol::new(&self.env, &"power"),
            ::soroban_sdk::Vec::from_array(&self.env, [exp.into_val(&self.env)]),
        )
    }
    pub fn try_power(
        &self,
        exp: &u32,
    ) -> Result<
        Result<I256, <I256 as soroban_sdk::TryFromVal<soroban_sdk::Env, soroban_sdk::Val>>::Error>,
        Result<soroban_sdk::Error, <soroban_sdk::Error as TryFrom<soroban_sdk::Error>>::Error>,
    > {
        use soroban_sdk::{FromVal, IntoVal};
        self.env.try_invoke_contract(
            &self.address,
            &soroban_sdk::Symbol::new(&self.env, &"power"),
            ::soroban_sdk::Vec::from_array(&self.env, [exp.into_val(&self.env)]),
        )
    }
}
#[doc(hidden)]
pub mod __power {
    use super::*;
    #[deprecated(note = "use `PowerContractClient::new(&env, &contract_id).power` instead")]
    pub extern "C" fn invoke_raw(
        env: soroban_sdk::Env,
        arg_0: soroban_sdk::Val,
    ) -> soroban_sdk::Val {
        <_ as soroban_sdk::IntoVal<
            soroban_sdk::Env,
            soroban_sdk::Val,
        >>::into_val(
            #[allow(deprecated)]
            &<super::PowerContract>::power(
                env.clone(),
                <_ as soroban_sdk::unwrap::UnwrapOptimized>::unwrap_optimized(
                    <_ as soroban_sdk::TryFromVal<
                        soroban_sdk::Env,
                        soroban_sdk::Val,
                    >>::try_from_val(&env, &arg_0),
                ),
            ),
            &env,
        )
    }
    #[deprecated(note = "use `PowerContractClient::new(&env, &contract_id).power` instead")]
    pub fn invoke_raw_slice(env: soroban_sdk::Env, args: &[soroban_sdk::Val]) -> soroban_sdk::Val {
        #[allow(deprecated)]
        invoke_raw(env, args[0usize])
    }
    use super::*;
}
