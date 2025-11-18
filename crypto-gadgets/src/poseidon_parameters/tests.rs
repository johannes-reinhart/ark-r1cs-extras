use ark_crypto_primitives::crh::{poseidon, CRHScheme};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use std::iter::zip;

pub fn test_poseidon_against_vector<F>(
    parameters: &PoseidonConfig<F>,
    input: &[F],
    expected_output: F,
) where
    F: PrimeField + Absorb,
{
    type PoseidonCRH<F> = poseidon::CRH<F>;

    let digest = PoseidonCRH::evaluate(parameters, input).unwrap();
    assert_eq!(digest, expected_output)
}

pub fn test_poseidon_against_vectors<F>(
    parameters: &PoseidonConfig<F>,
    inputs: &[&[F]],
    expected_outputs: &[F],
) where
    F: PrimeField + Absorb,
{
    for (input, expected_output) in zip(inputs, expected_outputs) {
        test_poseidon_against_vector(parameters, input, *expected_output);
    }
}
