//! Poseidon collision resistant hash function
//!
//! This includes a wrapper around ark-crypto-primitives poseidon CRH implementation
//! but with setup implemented: setup loads parameters from a precomputed list

use crate::poseidon_parameters::{poseidon_parameters, PoseidonConfigError};
use ark_crypto_primitives::crh::{poseidon as ark_poseidon, CRHScheme};
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::boxed::Box;
use ark_std::rand::Rng;
use ark_std::{end_timer, start_timer};
use core::borrow::Borrow;
use core::marker::PhantomData;

pub struct CRH<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl From<PoseidonConfigError> for Error {
    fn from(value: PoseidonConfigError) -> Self {
        Error::GenericError(Box::new(value))
    }
}

impl<F: PrimeField + Absorb> CRHScheme for CRH<F> {
    type Input = <ark_poseidon::CRH<F> as CRHScheme>::Input;
    type Output = <ark_poseidon::CRH<F> as CRHScheme>::Output;
    type Parameters = <ark_poseidon::CRH<F> as CRHScheme>::Parameters;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(poseidon_parameters()?)
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let evaluation_time = start_timer!(|| "Poseidon evaluation");
        let result = ark_poseidon::CRH::evaluate(parameters, input);
        end_timer!(evaluation_time);
        result
    }
}
