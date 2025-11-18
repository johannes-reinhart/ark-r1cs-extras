use crate::signature::SignatureScheme;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

pub trait SigVerifyGadget<S: SignatureScheme, ConstraintF: Field> {
    type InputVar: AllocVar<S::Input, ConstraintF>;

    type ParametersVar: AllocVar<S::Parameters, ConstraintF>;

    type PublicKeyVar: AllocVar<S::PublicKey, ConstraintF>;

    type SignatureVar: AllocVar<S::Signature, ConstraintF>;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[Self::InputVar],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

/// Signature verification circuit for a fixed public key
/// implementations of this trait can be more efficient for proving than
/// SigVerifyGadget, as the circuit can cache parts of the cicuit generation
pub trait SigVerifyCircuit<S: SignatureScheme, ConstraintF: Field>: Clone {
    type InputVar: AllocVar<S::Input, ConstraintF>;

    type ParametersVar: AllocVar<S::Parameters, ConstraintF>;

    type PublicKeyVar: AllocVar<S::PublicKey, ConstraintF>;

    type SignatureVar: AllocVar<S::Signature, ConstraintF>;

    fn new(parameters: &S::Parameters, public_key: &S::PublicKey) -> Self;

    fn generate_constraints(
        &self,
        message: &[Self::InputVar],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

#[cfg(test)]
pub(crate) mod test {
    use crate::signature::constraints::{SigVerifyCircuit, SigVerifyGadget};
    use crate::signature::SignatureScheme;
    use ark_ff::prelude::*;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::TracingMode::OnlyConstraints;
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem};
    use ark_std::test_rng;
    use tracing_subscriber::layer::SubscriberExt;

    pub(crate) fn sign_and_verify<F, S, SG>(message: &[S::Input])
    where
        F: PrimeField,
        S: SignatureScheme,
        SG: SigVerifyGadget<S, F>,
    {
        let mut layer = ConstraintLayer::default();
        layer.mode = OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, &message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, &message, &sig).unwrap());

        let cs = ConstraintSystem::<F>::new_ref();

        let parameters_var = SG::ParametersVar::new_constant(cs.clone(), parameters).unwrap();
        let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
        let pk_var = SG::PublicKeyVar::new_witness(cs.clone(), || Ok(&pk)).unwrap();
        let mut msg_var = Vec::new();
        for m in message {
            msg_var.push(SG::InputVar::new_witness(cs.clone(), || Ok(m)).unwrap())
        }
        let valid_sig_var = SG::verify(&parameters_var, &pk_var, &msg_var, &signature_var).unwrap();

        valid_sig_var.enforce_equal(&Boolean::<F>::TRUE).unwrap();
        let result = cs.is_satisfied().unwrap();
        assert!(
            result,
            "Constraint system not satisfied:\n{}",
            cs.which_is_unsatisfied().unwrap().unwrap()
        );
    }

    pub(crate) fn failed_verification<F, S, SG>(message: &[S::Input], bad_message: &[S::Input])
    where
        F: PrimeField,
        S: SignatureScheme,
        SG: SigVerifyGadget<S, F>,
    {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(!S::verify(&parameters, &pk, bad_message, &sig).unwrap());

        let cs = ConstraintSystem::<F>::new_ref();

        let parameters_var = SG::ParametersVar::new_constant(cs.clone(), parameters).unwrap();
        let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
        let pk_var = SG::PublicKeyVar::new_witness(cs.clone(), || Ok(&pk)).unwrap();
        let mut bad_msg_var = Vec::new();
        for m in bad_message {
            bad_msg_var.push(SG::InputVar::new_witness(cs.clone(), || Ok(m)).unwrap())
        }
        let valid_sig_var =
            SG::verify(&parameters_var, &pk_var, &bad_msg_var, &signature_var).unwrap();

        valid_sig_var.enforce_equal(&Boolean::<F>::FALSE).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    pub(crate) fn sign_and_verify_circuit<F, S, SG>(message: &[S::Input])
    where
        F: PrimeField,
        S: SignatureScheme,
        SG: SigVerifyCircuit<S, F>,
    {
        let mut layer = ConstraintLayer::default();
        layer.mode = OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, &message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, &message, &sig).unwrap());

        let cs = ConstraintSystem::<F>::new_ref();
        let verification_circuit = SG::new(&parameters, &pk);

        let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
        let mut msg_var = Vec::new();
        for m in message {
            msg_var.push(SG::InputVar::new_witness(cs.clone(), || Ok(m)).unwrap())
        }
        let valid_sig_var = verification_circuit
            .generate_constraints(&msg_var, &signature_var)
            .unwrap();

        valid_sig_var.enforce_equal(&Boolean::<F>::TRUE).unwrap();
        let result = cs.is_satisfied().unwrap();
        assert!(
            result,
            "Constraint system not satisfied:\n{}",
            cs.which_is_unsatisfied().unwrap().unwrap()
        );
    }

    pub(crate) fn failed_verification_circuit<F, S, SG>(
        message: &[S::Input],
        bad_message: &[S::Input],
    ) where
        F: PrimeField,
        S: SignatureScheme,
        SG: SigVerifyCircuit<S, F>,
    {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(!S::verify(&parameters, &pk, bad_message, &sig).unwrap());

        let cs = ConstraintSystem::<F>::new_ref();
        let verification_circuit = SG::new(&parameters, &pk);

        let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
        let mut bad_msg_var = Vec::new();
        for m in bad_message {
            bad_msg_var.push(SG::InputVar::new_witness(cs.clone(), || Ok(m)).unwrap())
        }
        let valid_sig_var = verification_circuit
            .generate_constraints(&bad_msg_var, &signature_var)
            .unwrap();

        valid_sig_var.enforce_equal(&Boolean::<F>::FALSE).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
