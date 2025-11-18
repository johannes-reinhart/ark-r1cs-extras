use crate::curve::scalar_mul::{scalar_mul_le, FixedBaseScalarMultiplicationCircuit};
use crate::signature::constraints::{SigVerifyCircuit, SigVerifyGadget};
use crate::signature::eddsa::constraints::{ParametersVar, PublicKeyVar, SignatureVar};
use crate::signature::eddsa::PoseidonEdDSA;
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

pub struct PoseidonEdDSAVerifyGadget<C> {
    #[doc(hidden)]
    _c: PhantomData<*const C>,
}

impl<P> PoseidonEdDSAVerifyGadget<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    fn compute_verifier_challenge(
        parameters: &ParametersVar<Projective<P>, GC<P>, PoseidonParametersVar<P::BaseField>>,
        prover_commitment: &GC<P>,
        public_key: &GC<P>,
        message: &[FpVar<P::BaseField>],
    ) -> Result<FpVar<P::BaseField>, SynthesisError> {
        let mut hash_input = Vec::new();
        if let Some(salt) = &parameters.salt {
            hash_input.extend_from_slice(&salt.to_constraint_field()?);
        }
        hash_input.extend_from_slice(&prover_commitment.to_constraint_field()?);
        hash_input.extend_from_slice(&public_key.to_constraint_field()?);
        hash_input.extend_from_slice(message);
        let digest = constraints::CRHGadget::evaluate(&parameters.crh_parameters, &hash_input)?;
        Ok(digest)
    }
}

impl<P> SigVerifyGadget<PoseidonEdDSA<Projective<P>>, P::BaseField> for PoseidonEdDSAVerifyGadget<P>
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
        let prover_commitment = signature.prover_commitment.clone();
        let lhs = scalar_mul_le(&parameters.generator, &prover_response.to_bits_le()?)?;
        let h = Self::compute_verifier_challenge(
            parameters,
            &prover_commitment,
            &public_key.pub_key,
            &message,
        )?;
        let rhs = scalar_mul_le(&public_key.pub_key, &h.to_bits_le()?)? + prover_commitment;

        lhs.is_eq(&rhs)
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "P: TECurveConfig"))]
pub struct PoseidonEdDSAVerifyCircuit<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    parameters_var: ParametersVar<Projective<P>, GC<P>, PoseidonParametersVar<P::BaseField>>,
    public_key_var: PublicKeyVar<Projective<P>, GC<P>>,
    scalar_mul_generator: FixedBaseScalarMultiplicationCircuit<P>,
    scalar_mul_pubkey: FixedBaseScalarMultiplicationCircuit<P>,
}

impl<P> SigVerifyCircuit<PoseidonEdDSA<Projective<P>>, P::BaseField>
    for PoseidonEdDSAVerifyCircuit<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    type InputVar = FpVar<P::BaseField>;
    type ParametersVar = ParametersVar<Projective<P>, GC<P>, PoseidonParametersVar<P::BaseField>>;
    type PublicKeyVar = PublicKeyVar<Projective<P>, GC<P>>;
    type SignatureVar = SignatureVar<Projective<P>, GC<P>>;

    fn new(
        parameters: &<PoseidonEdDSA<Projective<P>> as SignatureScheme>::Parameters,
        public_key: &<PoseidonEdDSA<Projective<P>> as SignatureScheme>::PublicKey,
    ) -> Self {
        let cs = ConstraintSystemRef::None;
        let parameters_var = ParametersVar::new_constant(cs.clone(), parameters).unwrap();
        let public_key_var = PublicKeyVar::new_constant(cs, public_key).unwrap();

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
            public_key_var,
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
        let prover_commitment = signature.prover_commitment.clone();
        let lhs = self
            .scalar_mul_generator
            .generate_constraints(&prover_response.to_bits_le()?)?;
        let h = PoseidonEdDSAVerifyGadget::compute_verifier_challenge(
            &self.parameters_var,
            &prover_commitment,
            &self.public_key_var.pub_key,
            &message,
        )?;
        let rhs = self
            .scalar_mul_pubkey
            .generate_constraints(&h.to_bits_le()?)?
            + prover_commitment;
        lhs.is_eq(&rhs)
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
    fn poseidon_eddsa_test() {
        type F = <EdwardsProjective as CurveGroup>::BaseField;
        let message = "Hi, I am an EdDSA signature!";
        sign_and_verify::<
            F,
            PoseidonEdDSA<EdwardsProjective>,
            PoseidonEdDSAVerifyGadget<EdwardsConfig>,
        >(message.as_bytes().to_field_elements().unwrap().as_slice());
        failed_verification::<
            F,
            PoseidonEdDSA<EdwardsProjective>,
            PoseidonEdDSAVerifyGadget<EdwardsConfig>,
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
    fn poseidon_eddsa_circuit_test() {
        type F = <EdwardsProjective as CurveGroup>::BaseField;
        let message = "Hi, I am an EdDSA signature!";
        sign_and_verify_circuit::<
            F,
            PoseidonEdDSA<EdwardsProjective>,
            PoseidonEdDSAVerifyCircuit<EdwardsConfig>,
        >(message.as_bytes().to_field_elements().unwrap().as_slice());
        failed_verification_circuit::<
            F,
            PoseidonEdDSA<EdwardsProjective>,
            PoseidonEdDSAVerifyCircuit<EdwardsConfig>,
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
