#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    // missing_docs
)]
#![forbid(unsafe_code)]

#[cfg(feature = "poseidon-parameters")]
pub mod poseidon_parameters;

#[cfg(feature = "crh")]
pub mod crh;

#[cfg(feature = "signature")]
pub mod signature;

#[cfg(feature = "r1cs")]
pub mod curve;
