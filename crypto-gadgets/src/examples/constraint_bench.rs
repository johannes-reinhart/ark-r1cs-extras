use ark_crypto_gadgets::curve::scalar_mul::scalar_mul_le_fixed_base;
use ark_crypto_gadgets::signature::constraints::SigVerifyGadget;
use ark_crypto_gadgets::signature::eddsa::constraints::bowe_hopwood::BHEdDSAVerifyGadget;
use ark_crypto_gadgets::signature::eddsa::constraints::poseidon::PoseidonEdDSAVerifyGadget;
use ark_crypto_gadgets::signature::eddsa::{BHEdDSA, PoseidonEdDSA};
use ark_crypto_gadgets::signature::schnorr::constraints::bowe_hopwood::BHSchnorrVerifyGadget;
use ark_crypto_gadgets::signature::schnorr::constraints::poseidon::PoseidonSchnorrVerifyGadget;
use ark_crypto_gadgets::signature::schnorr::{BHSchnorr, PoseidonSchnorr};
use ark_crypto_gadgets::signature::SignatureScheme;
use ark_crypto_primitives::crh::pedersen;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::twisted_edwards::{Projective, TECurveConfig};
use ark_ec::PrimeGroup;
/// Prints number of R1CS for various crypto operations
use ark_ff::{BitIteratorLE, PrimeField, ToConstraintField};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal};
use ark_std::test_rng;
use core::fmt;

#[derive(Clone, Debug)]
struct ConstraintCount {
    num_constraints: usize,
    num_witness_vars: usize,
    num_input_vars: usize,
}

impl fmt::Display for ConstraintCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConstraintCount")
            .field("num_constraints", &self.num_constraints)
            .field("num_witness_vars", &self.num_witness_vars)
            .field("num_input_vars", &self.num_input_vars)
            .finish()
    }
}

fn signature_verification<F, S, SG>(message: &[S::Input], fixed_pubkey: bool) -> ConstraintCount
where
    F: PrimeField,
    S: SignatureScheme,
    SG: SigVerifyGadget<S, F>,
{
    let rng = &mut test_rng();
    let parameters = S::setup::<_>(rng).unwrap();
    let (pk, sk) = S::keygen(&parameters, rng).unwrap();
    let sig = S::sign(&parameters, &sk, &message, rng).unwrap();

    let cs = ConstraintSystem::<F>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);

    let parameters_var = SG::ParametersVar::new_constant(cs.clone(), parameters).unwrap();
    let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
    let pk_var = match fixed_pubkey {
        true => SG::PublicKeyVar::new_constant(cs.clone(), &pk),
        false => SG::PublicKeyVar::new_witness(cs.clone(), || Ok(&pk)),
    }
    .unwrap();
    let mut msg_var = Vec::new();
    for m in message {
        msg_var.push(SG::InputVar::new_witness(cs.clone(), || Ok(m)).unwrap())
    }
    let _valid_sig_var = SG::verify(&parameters_var, &pk_var, &msg_var, &signature_var).unwrap();
    cs.finalize();

    ConstraintCount {
        num_constraints: cs.num_constraints(),
        num_witness_vars: cs.num_witness_variables(),
        num_input_vars: cs.num_instance_variables(),
    }
}

fn poseidon_schnorr_signature_verification<P>() -> ConstraintCount
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    let message = "Test";
    let c = signature_verification::<
        P::BaseField,
        PoseidonSchnorr<Projective<P>>,
        PoseidonSchnorrVerifyGadget<P>,
    >(
        message.as_bytes().to_field_elements().unwrap().as_slice(),
        false,
    );
    c
}

fn poseidon_schnorr_signature_verification_fixed<P>() -> ConstraintCount
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    let message = "Test";
    let c = signature_verification::<
        P::BaseField,
        PoseidonSchnorr<Projective<P>>,
        PoseidonSchnorrVerifyGadget<P>,
    >(
        message.as_bytes().to_field_elements().unwrap().as_slice(),
        true,
    );
    c
}

#[derive(Clone)]
struct Window;
impl pedersen::Window for Window {
    const WINDOW_SIZE: usize = 14; // this is in bits, make as large as possible
    const NUM_WINDOWS: usize = 40;
}

fn bh_schnorr_signature_verification<P>() -> ConstraintCount
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    let message = "Test";
    let c = signature_verification::<
        P::BaseField,
        BHSchnorr<P, Window>,
        BHSchnorrVerifyGadget<P, Window>,
    >(message.as_bytes(), false);
    c
}

fn bh_schnorr_signature_verification_fixed<P>() -> ConstraintCount
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    let message = "Test";
    let c = signature_verification::<
        P::BaseField,
        BHSchnorr<P, Window>,
        BHSchnorrVerifyGadget<P, Window>,
    >(message.as_bytes(), true);
    c
}

fn poseidon_eddsa_signature_verification<P>() -> ConstraintCount
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    let message = "Test";
    let c = signature_verification::<
        P::BaseField,
        PoseidonEdDSA<Projective<P>>,
        PoseidonEdDSAVerifyGadget<P>,
    >(
        message.as_bytes().to_field_elements().unwrap().as_slice(),
        false,
    );
    c
}

fn poseidon_eddsa_signature_verification_fixed<P>() -> ConstraintCount
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    let message = "Test";
    let c = signature_verification::<
        P::BaseField,
        PoseidonEdDSA<Projective<P>>,
        PoseidonEdDSAVerifyGadget<P>,
    >(
        message.as_bytes().to_field_elements().unwrap().as_slice(),
        true,
    );
    c
}

fn bh_eddsa_signature_verification<P>() -> ConstraintCount
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    let message = "Test";
    let c = signature_verification::<
        P::BaseField,
        BHEdDSA<P, Window>,
        BHEdDSAVerifyGadget<P, Window>,
    >(message.as_bytes(), false);
    c
}

fn bh_eddsa_signature_verification_fixed<P>() -> ConstraintCount
where
    P: TECurveConfig,
    P::BaseField: PrimeField + Absorb,
{
    let message = "Test";
    let c = signature_verification::<
        P::BaseField,
        BHEdDSA<P, Window>,
        BHEdDSAVerifyGadget<P, Window>,
    >(message.as_bytes(), true);
    c
}

fn scalar_mul_fixed<P>() -> ConstraintCount
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    let base = Projective::<P>::generator();
    let scalar = P::ScalarField::from(153);
    let cs = ConstraintSystem::<P::BaseField>::new_ref();

    let scalar_bits: Vec<_> = BitIteratorLE::new(scalar.into_bigint()).collect();
    let scalar_bits_var = Vec::new_witness(cs.clone(), || Ok(scalar_bits)).unwrap();

    let _result_var = scalar_mul_le_fixed_base(base, &scalar_bits_var).unwrap();

    cs.finalize();

    ConstraintCount {
        num_constraints: cs.num_constraints(),
        num_witness_vars: cs.num_witness_variables(),
        num_input_vars: cs.num_instance_variables(),
    }
}

macro_rules! benchmark_all_edwards_configs {
    ($benchmark_fn:ident) => {{
        println!("Constraints for: {}", stringify!($benchmark_fn));

        use ark_ed_on_bn124::EdwardsConfig as EdConfig124;
        use ark_ed_on_bn183::EdwardsConfig as EdConfig183;
        use ark_ed_on_bn254::EdwardsConfig as EdConfig254;
        use ark_ed_on_ed181::EdwardsConfig as EdConfig181;
        use ark_ed_on_ed58::EdwardsConfig as EdConfig58;
        use ark_ed_on_ed61::EdwardsConfig as EdConfig61;
        use ark_ed_on_ed97::EdwardsConfig as EdConfig97;

        let results = vec![
            ("EdwardsProjective254", $benchmark_fn::<EdConfig254>()),
            ("EdwardsProjective183", $benchmark_fn::<EdConfig183>()),
            ("EdwardsProjective124", $benchmark_fn::<EdConfig124>()),
            ("EdwardsProjective181", $benchmark_fn::<EdConfig181>()),
            ("EdwardsProjective97", $benchmark_fn::<EdConfig97>()),
            ("EdwardsProjective61", $benchmark_fn::<EdConfig61>()),
            ("EdwardsProjective58", $benchmark_fn::<EdConfig58>()),
        ];

        for (curve_name, count) in results {
            println!("{}: {}", curve_name, count);
        }
    }};
}

fn main() {
    println!("Snark crypto constraint benchmarks");
    println!("Signature verification: ");

    benchmark_all_edwards_configs!(poseidon_schnorr_signature_verification);
    benchmark_all_edwards_configs!(poseidon_schnorr_signature_verification_fixed);
    benchmark_all_edwards_configs!(bh_schnorr_signature_verification);
    benchmark_all_edwards_configs!(bh_schnorr_signature_verification_fixed);

    benchmark_all_edwards_configs!(poseidon_eddsa_signature_verification);
    benchmark_all_edwards_configs!(poseidon_eddsa_signature_verification_fixed);
    benchmark_all_edwards_configs!(bh_eddsa_signature_verification);
    benchmark_all_edwards_configs!(bh_eddsa_signature_verification_fixed);

    benchmark_all_edwards_configs!(scalar_mul_fixed);
}
