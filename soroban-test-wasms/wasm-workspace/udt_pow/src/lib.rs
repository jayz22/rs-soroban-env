#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Env, Symbol, I256};

#[contracttype]
pub struct State {
    pub count: I256,
    pub last_exp: u32,
}

const STATE: Symbol = symbol_short!("STATE");

#[contract]
pub struct PowerContract;

#[contractimpl]
impl PowerContract {
    pub fn power(env: Env, exp: u32) -> I256 {
        // Get the current state.
        let mut state: State = env.storage().instance().get(&STATE).unwrap();

        // Compute the power.
        state.count = state.count.pow(exp);
        state.last_exp = exp;

        // Store the results.
        env.storage().instance().set(&STATE, &state);

        state.count
    }
}
