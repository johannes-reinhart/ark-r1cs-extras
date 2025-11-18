use crate::curve::scalar_mul::{scalar_mul_le, FixedBaseScalarMultiplicationCircuit};
use crate::signature::constraints::{SigVerifyCircuit, SigVerifyGadget};
use crate::signature::eddsa::constraints::{ParametersVar, PublicKeyVar, SignatureVar};
use crate::signature::eddsa::BHEdDSA;
use crate::signature::SignatureScheme;
use ark_crypto_primitives::crh::pedersen::Window;
use ark_crypto_primitives::crh::{bowe_hopwood, CRHSchemeGadget};
use ark_ec::twisted_edwards::{Projective, TECurveConfig};
use ark_ec::{AffineRepr, CurveConfig};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;
use core::marker::PhantomData;
use derivative::Derivative;

type GC<P> = AffineVar<P, FpVar<<P as CurveConfig>::BaseField>>;
type BHParametersVar<P, W> = bowe_hopwood::constraints::ParametersVar<P, W>;

pub struct BHEdDSAVerifyGadget<P, W> {
    #[doc(hidden)]
    _p: PhantomData<*const P>,
    #[doc(hidden)]
    _w: PhantomData<*const W>,
}

impl<P, W> BHEdDSAVerifyGadget<P, W>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
    W: Window,
{
    fn compute_verifier_challenge(
        parameters: &ParametersVar<Projective<P>, GC<P>, BHParametersVar<P, W>>,
        prover_commitment: &GC<P>,
        public_key: &GC<P>,
        message: &[UInt8<P::BaseField>],
    ) -> Result<FpVar<P::BaseField>, SynthesisError> {
        let mut hash_input = Vec::new();
        if let Some(salt) = &parameters.salt {
            hash_input.extend_from_slice(salt);
        }
        hash_input.extend_from_slice(&prover_commitment.to_bytes_le()?);
        hash_input.extend_from_slice(&public_key.to_bytes_le()?);
        hash_input.extend_from_slice(message);
        let digest = bowe_hopwood::constraints::CRHGadget::evaluate(
            &parameters.crh_parameters,
            &hash_input,
        )?;
        Ok(digest)
    }
}

impl<P, W> SigVerifyGadget<BHEdDSA<P, W>, P::BaseField> for BHEdDSAVerifyGadget<P, W>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
    W: Window,
{
    type InputVar = UInt8<P::BaseField>;
    type ParametersVar = ParametersVar<Projective<P>, GC<P>, BHParametersVar<P, W>>;
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
pub struct BHEdDSAVerifyCircuit<P, W>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
    W: Window,
{
    parameters_var: ParametersVar<Projective<P>, GC<P>, BHParametersVar<P, W>>,
    public_key_var: PublicKeyVar<Projective<P>, GC<P>>,
    scalar_mul_generator: FixedBaseScalarMultiplicationCircuit<P>,
    scalar_mul_pubkey: FixedBaseScalarMultiplicationCircuit<P>,
}

impl<P, W> SigVerifyCircuit<BHEdDSA<P, W>, P::BaseField> for BHEdDSAVerifyCircuit<P, W>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
    W: Window,
{
    type InputVar = UInt8<P::BaseField>;
    type ParametersVar = ParametersVar<Projective<P>, GC<P>, BHParametersVar<P, W>>;
    type PublicKeyVar = PublicKeyVar<Projective<P>, GC<P>>;
    type SignatureVar = SignatureVar<Projective<P>, GC<P>>;

    fn new(
        parameters: &<BHEdDSA<P, W> as SignatureScheme>::Parameters,
        public_key: &<BHEdDSA<P, W> as SignatureScheme>::PublicKey,
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
        let h = BHEdDSAVerifyGadget::compute_verifier_challenge(
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
    use ark_crypto_primitives::crh::pedersen;
    use ark_ec::CurveGroup;
    use ark_ed_on_bn254::{EdwardsConfig, EdwardsProjective};

    #[derive(Clone)]
    struct Window;
    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 63; // this is in bits, make as large as possible
        const NUM_WINDOWS: usize = 8;
    }

    #[test]
    fn bowe_hopwood_eddsa_test() {
        type F = <EdwardsProjective as CurveGroup>::BaseField;
        let message = "Hi, I am a EdDSA signature!";
        sign_and_verify::<
            F,
            BHEdDSA<EdwardsConfig, Window>,
            BHEdDSAVerifyGadget<EdwardsConfig, Window>,
        >(message.as_bytes());
        failed_verification::<
            F,
            BHEdDSA<EdwardsConfig, Window>,
            BHEdDSAVerifyGadget<EdwardsConfig, Window>,
        >(message.as_bytes(), "Bad message".as_bytes());
    }

    #[test]
    fn bowe_hopwood_eddsa_circuit_test() {
        type F = <EdwardsProjective as CurveGroup>::BaseField;
        let message = "Hi, I am an EdDSA signature!";
        sign_and_verify_circuit::<
            F,
            BHEdDSA<EdwardsConfig, Window>,
            BHEdDSAVerifyCircuit<EdwardsConfig, Window>,
        >(message.as_bytes());
        failed_verification_circuit::<
            F,
            BHEdDSA<EdwardsConfig, Window>,
            BHEdDSAVerifyCircuit<EdwardsConfig, Window>,
        >(message.as_bytes(), "Bad message".as_bytes());
    }
}
