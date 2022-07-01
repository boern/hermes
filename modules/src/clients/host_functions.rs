use crate::core::ics02_client::error::Error;
use crate::prelude::*;
use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;

/// This trait captures all the functions that the host chain should provide for
/// crypto operations.
pub trait HostFunctionsProvider: Clone + Send + Sync + Default {
    /// Keccak 256 hash function
    fn keccak_256(input: &[u8]) -> [u8; 32];

    /// Compressed Ecdsa public key recovery from a signature
    fn secp256k1_ecdsa_recover_compressed(
        signature: &[u8; 65],
        value: &[u8; 32],
    ) -> Option<Vec<u8>>;

    /// Recover the ED25519 pubkey that produced this signature, given a arbitrarily sized message
    fn ed25519_verify(signature: &[u8; 64], msg: &[u8], pubkey: &[u8]) -> bool;

    /// This function should verify membership in a trie proof using parity's sp-trie package
    /// with a BlakeTwo256 Hasher
    fn verify_membership_trie_proof(
        root: &[u8; 32],
        proof: &[Vec<u8>],
        key: &[u8],
        value: &[u8],
    ) -> Result<(), Error>;

    /// This function should verify non membership in a trie proof using parity's sp-trie package
    /// with a BlakeTwo256 Hasher
    fn verify_non_membership_trie_proof(
        root: &[u8; 32],
        proof: &[Vec<u8>],
        key: &[u8],
    ) -> Result<(), Error>;

    /// Conduct a 256-bit Sha2 hash
    fn sha256_digest(data: &[u8]) -> [u8; 32];

    /// The SHA-256 hash algorithm
    fn sha2_256(message: &[u8]) -> [u8; 32];

    /// The SHA-512 hash algorithm
    fn sha2_512(message: &[u8]) -> [u8; 64];

    /// The SHA-512 hash algorithm with its output truncated to 256 bits.
    fn sha2_512_truncated(message: &[u8]) -> [u8; 32];

    /// SHA-3-512 hash function.
    fn sha3_512(message: &[u8]) -> [u8; 64];

    /// Ripemd160 hash function.
    fn ripemd160(message: &[u8]) -> [u8; 20];
}

/// This is a work around that allows us to have one super trait [`HostFunctionsProvider`]
/// that encapsulates all the needed host functions by different subsytems, and then
/// implement the needed traits through this wrapper.
#[derive(Clone, Default)]
pub struct HostFunctionsManager<T: HostFunctionsProvider>(PhantomData<T>);

// implementation for beefy host functions
// #[cfg(any(test, feature = "mocks", feature = "ics11_beefy"))]
// impl<T> beefy_client::traits::HostFunctions for HostFunctionsManager<T>
//     where
//         T: HostFunctionsProvider,
// {
//     fn keccak_256(input: &[u8]) -> [u8; 32] {
//         T::keccak_256(input)
//     }
//
//     fn secp256k1_ecdsa_recover_compressed(
//         signature: &[u8; 65],
//         value: &[u8; 32],
//     ) -> Option<Vec<u8>> {
//         T::secp256k1_ecdsa_recover_compressed(signature, value)
//     }
// }

impl<T> Debug for HostFunctionsManager<T>
where
    T: HostFunctionsProvider,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "HostFunctionsManager!")
    }
}

// implementation for tendermint functions
impl<T> tendermint_light_client_verifier::host_functions::HostFunctionsProvider
    for HostFunctionsManager<T>
where
    T: HostFunctionsProvider + 'static,
{
    fn sha2_256(preimage: &[u8]) -> [u8; 32] {
        T::sha256_digest(preimage)
    }

    fn ed25519_verify(sig: &[u8], msg: &[u8], pub_key: &[u8]) -> Result<(), ()> {
        let mut signature = [0u8; 64];
        signature.copy_from_slice(sig);
        match T::ed25519_verify(&signature, msg, pub_key) {
            true => Ok(()),
            false => Err(()),
        }
    }

    fn secp256k1_verify(_sig: &[u8], _message: &[u8], _public: &[u8]) -> Result<(), ()> {
        unimplemented!()
    }
}

// implementation for ics23
impl<H> ics23::HostFunctionsProvider for HostFunctionsManager<H>
where
    H: HostFunctionsProvider,
{
    fn sha2_256(message: &[u8]) -> [u8; 32] {
        H::sha2_256(message)
    }

    fn sha2_512(message: &[u8]) -> [u8; 64] {
        H::sha2_512(message)
    }

    fn sha2_512_truncated(message: &[u8]) -> [u8; 32] {
        H::sha2_512_truncated(message)
    }

    fn sha3_512(message: &[u8]) -> [u8; 64] {
        H::sha3_512(message)
    }

    fn ripemd160(message: &[u8]) -> [u8; 20] {
        H::ripemd160(message)
    }
}

/// TODO Add templ tendermint provider just can temp use
#[derive(Debug, Default, Clone)]
pub struct TempTendermintProvider;

// implementation for tendermint functions
impl tendermint_light_client_verifier::host_functions::HostFunctionsProvider
    for TempTendermintProvider
{
    fn sha2_256(preimage: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }

    fn ed25519_verify(sig: &[u8], msg: &[u8], pub_key: &[u8]) -> Result<(), ()> {
        Ok(())
    }

    fn secp256k1_verify(_sig: &[u8], _message: &[u8], _public: &[u8]) -> Result<(), ()> {
        unimplemented!()
    }
}

impl HostFunctionsProvider for TempTendermintProvider {
    fn keccak_256(input: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }

    fn secp256k1_ecdsa_recover_compressed(
        signature: &[u8; 65],
        value: &[u8; 32],
    ) -> Option<Vec<u8>> {
        None
    }

    fn ed25519_verify(signature: &[u8; 64], msg: &[u8], pubkey: &[u8]) -> bool {
        true
    }

    fn verify_membership_trie_proof(
        root: &[u8; 32],
        proof: &[Vec<u8>],
        key: &[u8],
        value: &[u8],
    ) -> Result<(), Error> {
        Ok(())
    }

    fn verify_non_membership_trie_proof(
        root: &[u8; 32],
        proof: &[Vec<u8>],
        key: &[u8],
    ) -> Result<(), Error> {
        Ok(())
    }

    fn sha256_digest(data: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }

    fn sha2_256(message: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }

    fn sha2_512(message: &[u8]) -> [u8; 64] {
        [0u8; 64]
    }

    fn sha2_512_truncated(message: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }

    fn sha3_512(message: &[u8]) -> [u8; 64] {
        [0u8; 64]
    }

    fn ripemd160(message: &[u8]) -> [u8; 20] {
        [0u8; 20]
    }
}
