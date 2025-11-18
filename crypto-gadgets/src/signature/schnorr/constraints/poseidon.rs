use crate::curve::scalar_mul::{scalar_mul_le, FixedBaseScalarMultiplicationCircuit};
use crate::signature::constraints::{SigVerifyCircuit, SigVerifyGadget};
use crate::signature::schnorr::constraints::{ParametersVar, PublicKeyVar, SignatureVar};
use crate::signature::schnorr::PoseidonSchnorr;
use crate::signature::SignatureScheme;
use ark_crypto_primitives::crh::poseidon::constraints;
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::twisted_edwards::{Projective, TECurveConfig};
use ark_ec::{AffineRepr, CurveConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;
use core::marker::PhantomData;
use derivative::Derivative;

type GC<P> = AffineVar<P, FpVar<<P as CurveConfig>::BaseField>>;
type PoseidonParametersVar<F> = constraints::CRHParametersVar<F>;

pub struct PoseidonSchnorrVerifyGadget<P> {
    #[doc(hidden)]
    _p: PhantomData<*const P>,
}

impl<P> PoseidonSchnorrVerifyGadget<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    fn compute_verifier_challenge(
        parameters: &ParametersVar<Projective<P>, GC<P>, PoseidonParametersVar<P::BaseField>>,
        prover_commitment: &GC<P>,
        message: &[FpVar<P::BaseField>],
    ) -> Result<FpVar<P::BaseField>, SynthesisError> {
        let mut hash_input = Vec::new();
        if let Some(salt) = &parameters.salt {
            hash_input.extend_from_slice(&salt.to_constraint_field()?);
        }
        hash_input.extend_from_slice(&prover_commitment.to_constraint_field()?);
        hash_input.extend_from_slice(message);
        let digest = constraints::CRHGadget::evaluate(&parameters.crh_parameters, &hash_input)?;
        Ok(digest)
    }
}

impl<P> SigVerifyGadget<PoseidonSchnorr<Projective<P>>, P::BaseField>
    for PoseidonSchnorrVerifyGadget<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    type InputVar = FpVar<P::BaseField>;
    type ParametersVar = ParametersVar<Projective<P>, GC<P>, PoseidonParametersVar<P::BaseField>>;
    type PublicKeyVar = PublicKeyVar<Projective<P>, GC<P>>;
    type SignatureVar = SignatureVar<Projective<P>, GC<P>>;

    #[tracing::instrument(target = "r1cs", skip(parameters))]
    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[Self::InputVar],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<P::BaseField>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();
        let mut claimed_prover_commitment =
            scalar_mul_le(&parameters.generator, &prover_response.to_bits_le()?)?;
        let public_key_times_verifier_challenge =
            scalar_mul_le(&public_key.pub_key, &verifier_challenge.to_bits_le()?)?;
        claimed_prover_commitment += &public_key_times_verifier_challenge;

        let obtained_verifier_challenge =
            Self::compute_verifier_challenge(parameters, &claimed_prover_commitment, &message)?;

        obtained_verifier_challenge.is_eq(&verifier_challenge)
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "P: TECurveConfig"))]
pub struct PoseidonSchnorrVerifyCircuit<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    parameters_var: ParametersVar<Projective<P>, GC<P>, PoseidonParametersVar<P::BaseField>>,
    scalar_mul_generator: FixedBaseScalarMultiplicationCircuit<P>,
    scalar_mul_pubkey: FixedBaseScalarMultiplicationCircuit<P>,
}

impl<P> SigVerifyCircuit<PoseidonSchnorr<Projective<P>>, P::BaseField>
    for PoseidonSchnorrVerifyCircuit<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    type InputVar = FpVar<P::BaseField>;
    type ParametersVar = ParametersVar<Projective<P>, GC<P>, PoseidonParametersVar<P::BaseField>>;
    type PublicKeyVar = PublicKeyVar<Projective<P>, GC<P>>;
    type SignatureVar = SignatureVar<Projective<P>, GC<P>>;

    fn new(
        parameters: &<PoseidonSchnorr<Projective<P>> as SignatureScheme>::Parameters,
        public_key: &<PoseidonSchnorr<Projective<P>> as SignatureScheme>::PublicKey,
    ) -> Self {
        let cs = ConstraintSystemRef::None;
        let parameters_var = ParametersVar::new_constant(cs.clone(), parameters).unwrap();

        let scalar_mul_generator = FixedBaseScalarMultiplicationCircuit::new(
            parameters.generator.into(),
            P::BaseField::MODULUS_BIT_SIZE as usize,
        );
        let scalar_mul_pubkey = FixedBaseScalarMultiplicationCircuit::new(
            public_key.into_group(),
            P::BaseField::MODULUS_BIT_SIZE as usize,
        );

        Self {
            parameters_var,
            scalar_mul_generator,
            scalar_mul_pubkey,
        }
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn generate_constraints(
        &self,
        message: &[Self::InputVar],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<P::BaseField>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();
        let mut claimed_prover_commitment = self
            .scalar_mul_generator
            .generate_constraints(&prover_response.to_bits_le()?)?;
        let public_key_times_verifier_challenge = self
            .scalar_mul_pubkey
            .generate_constraints(&verifier_challenge.to_bits_le()?)?;
        claimed_prover_commitment += &public_key_times_verifier_challenge;

        let obtained_verifier_challenge = PoseidonSchnorrVerifyGadget::compute_verifier_challenge(
            &self.parameters_var,
            &claimed_prover_commitment,
            &message,
        )?;

        obtained_verifier_challenge.is_eq(&verifier_challenge)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::signature::constraints::test::*;
    use ark_ec::CurveGroup;
    use ark_ed_on_bn254::{EdwardsConfig, EdwardsProjective};
    use ark_ff::ToConstraintField;

    #[test]
    fn poseidon_schnorr_test() {
        type F = <EdwardsProjective as CurveGroup>::BaseField;
        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify::<
            F,
            PoseidonSchnorr<EdwardsProjective>,
            PoseidonSchnorrVerifyGadget<EdwardsConfig>,
        >(message.as_bytes().to_field_elements().unwrap().as_slice());
        failed_verification::<
            F,
            PoseidonSchnorr<EdwardsProjective>,
            PoseidonSchnorrVerifyGadget<EdwardsConfig>,
        >(
            message.as_bytes().to_field_elements().unwrap().as_slice(),
            "Bad message"
                .as_bytes()
                .to_field_elements()
                .unwrap()
                .as_slice(),
        );
    }

    #[test]
    fn poseidon_schnorr_circuit_test() {
        type F = <EdwardsProjective as CurveGroup>::BaseField;
        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify_circuit::<
            F,
            PoseidonSchnorr<EdwardsProjective>,
            PoseidonSchnorrVerifyCircuit<EdwardsConfig>,
        >(message.as_bytes().to_field_elements().unwrap().as_slice());
        failed_verification_circuit::<
            F,
            PoseidonSchnorr<EdwardsProjective>,
            PoseidonSchnorrVerifyCircuit<EdwardsConfig>,
        >(
            message.as_bytes().to_field_elements().unwrap().as_slice(),
            "Bad message"
                .as_bytes()
                .to_field_elements()
                .unwrap()
                .as_slice(),
        );
    }
}
