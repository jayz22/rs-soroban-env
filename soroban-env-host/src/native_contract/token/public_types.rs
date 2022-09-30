use crate::budget::CostType;
use crate::host::Host;
use crate::native_contract::base_types::{AccountId, Bytes, BytesN, Map, Vec};
use crate::native_contract::invoker::{invoker, Invoker};
use crate::native_contract::token::error::Error;
use soroban_env_common::{Symbol, TryIntoVal};
use soroban_native_sdk_macros::contracttype;

#[derive(Clone)]
#[contracttype]
pub struct Ed25519Signature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
}

#[derive(Clone)]
#[contracttype]
pub struct AccountSignatures {
    pub account_id: AccountId,
    pub signatures: Vec,
}

#[derive(Clone)]
#[contracttype]
pub enum Signature {
    Invoker,
    Ed25519(Ed25519Signature),
    Account(AccountSignatures),
}

impl Signature {
    pub fn get_identifier(&self, env: &Host) -> Result<Identifier, Error> {
        Ok(match self {
            Signature::Invoker => match invoker(env)? {
                Invoker::Account(a) => Identifier::Account(a),
                Invoker::Contract(c) => Identifier::Contract(c),
            },
            Signature::Ed25519(kea) => Identifier::Ed25519(kea.public_key.clone()),
            Signature::Account(kaa) => Identifier::Account(kaa.account_id.clone()),
        })
    }

    pub fn get_account_id(&self, env: &Host) -> Result<AccountId, Error> {
        match self {
            Signature::Account(acc) => Ok(acc.account_id.clone()),
            Signature::Invoker => match invoker(env)? {
                Invoker::Account(a) => Ok(a),
                Invoker::Contract(_) => Err(Error::ContractError),
            },
            _ => Err(Error::ContractError),
        }
    }
}

#[derive(Clone, PartialEq)]
#[contracttype]
pub enum Identifier {
    Contract(BytesN<32>),
    Ed25519(BytesN<32>),
    Account(AccountId),
}

#[derive(Clone)]
#[contracttype]
pub struct SignaturePayloadV0 {
    pub network: Bytes,
    pub contract: BytesN<32>,
    pub name: Symbol,
    pub args: Vec,
}

#[derive(Clone)]
#[contracttype]
pub enum SignaturePayload {
    V0(SignaturePayloadV0),
}

#[derive(Clone)]
#[contracttype]
pub struct TokenMetadata {
    pub name: Bytes,
    pub symbol: Bytes,
    pub decimals: u32,
}

#[derive(Clone)]
#[contracttype]
pub struct AlphaNum4Metadata {
    pub asset_code: BytesN<4>,
    pub issuer: AccountId,
}

#[derive(Clone)]
#[contracttype]
pub struct AlphaNum12Metadata {
    pub asset_code: BytesN<12>,
    pub issuer: AccountId,
}

#[derive(Clone)]
#[contracttype]
pub enum ClassicMetadata {
    Native,
    AlphaNum4(AlphaNum4Metadata),
    AlphaNum12(AlphaNum12Metadata),
}

#[derive(Clone)]
#[contracttype]
pub enum Metadata {
    Token(TokenMetadata),
    Native,
    AlphaNum4(AlphaNum4Metadata),
    AlphaNum12(AlphaNum12Metadata),
}
