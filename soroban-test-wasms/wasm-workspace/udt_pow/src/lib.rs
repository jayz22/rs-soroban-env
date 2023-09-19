#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Env, Symbol, I256};

// Custom contract data
#[contracttype]
struct State {
    pub value: I256,
    pub exp: u32,
}

const STATE: Symbol = symbol_short!("STATE");

#[contract]
pub struct PowerContract;

#[contractimpl]
impl PowerContract {
    pub fn power(env: Env, exp: u32) {
        // 1. Get the current state from the storage
        let mut state: State = env.storage().instance().get(&STATE).unwrap();

        // 2. Compute the power
        state.value = state.value.pow(exp);
        state.exp = exp;

        // 3. Write result back to the storage
        env.storage().instance().set(&STATE, &state);
    }
}
