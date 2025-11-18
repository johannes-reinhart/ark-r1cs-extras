use crate::crh::poseidon;
use crate::signature::SignatureScheme;
use ark_crypto_primitives::crh::pedersen::Window;
use ark_crypto_primitives::crh::{bowe_hopwood, CRHScheme};
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::Error;
use ark_ec::twisted_edwards::{Projective, TECurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{fields::PrimeField, BigInteger, ToConstraintField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{end_timer, marker::PhantomData, ops::Mul, rand::Rng, start_timer};
use core::fmt::Debug;
use derivative::Derivative;

/// Wrapper around ark-crypto-primitives Schnorr implementation
pub(crate) mod wrapped;

#[cfg(feature = "r1cs")]
pub mod constraints;

// pub struct Schnorr<C: CurveGroup, D: Digest> {
//     _group: PhantomData<C>,
//     _hash: PhantomData<D>,
// }

#[derive(Derivative)]
#[derivative(Clone(bound = "C: CurveGroup, P: Clone + CanonicalSerialize + CanonicalDeserialize"))]
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<C, P>
where
    C: CurveGroup,
    P: Clone + CanonicalSerialize + CanonicalDeserialize + Sync,
{
    pub generator: C::Affine,
    pub salt: Option<[u8; 32]>,
    pub crh_parameters: P,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

#[derive(Clone, Default, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey<C: CurveGroup>(pub C::ScalarField);

#[derive(Clone, Default, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<C: CurveGroup> {
    pub prover_response: C::ScalarField, // prover response represented as scalar field, as it acts as a scalar (exponent) in the verification equation
    pub verifier_challenge: C::BaseField, // verifier challenge represented as base field, as hash function output is expected to have same output size (indeed for Poseidon or Pedersen hash, it is the same size)
}

/// Adapter for Schnorr Signature
///
/// The Schnorr signatures for different hash functions only differ in the computation of
/// the verifier challenge. As the hash function might have different input types,
/// not only the serialization of the message, but also the serialization of the
/// prover commitment and the salt are affected
pub trait SchnorrAdapter {
    type C: CurveGroup;
    type Input: Clone;
    type CRH: CRHScheme;

    fn compute_verifier_challenge(
        parameters: &Parameters<Self::C, <Self::CRH as CRHScheme>::Parameters>,
        prover_commitment: &Self::C,
        message: &[Self::Input],
    ) -> Result<<Self::C as CurveGroup>::BaseField, Error>;
}

pub struct BHSchnorrAdapter<P: TECurveConfig, W: Window> {
    _p: PhantomData<*const P>,
    _w: PhantomData<*const W>,
}

impl<P, W> SchnorrAdapter for BHSchnorrAdapter<P, W>
where
    P: TECurveConfig,
    W: Window,
{
    type C = Projective<P>;
    type Input = u8;
    type CRH = bowe_hopwood::CRH<P, W>;

    fn compute_verifier_challenge(
        parameters: &Parameters<Self::C, <Self::CRH as CRHScheme>::Parameters>,
        prover_commitment: &Self::C,
        message: &[Self::Input],
    ) -> Result<<Self::C as CurveGroup>::BaseField, Error> {
        let verifier_challenge_time = start_timer!(|| "Verifier Challenge");
        // Hash everything to get verifier challenge.
        let mut hash_input = Vec::new();

        if let Some(salt) = parameters.salt {
            salt.serialize_uncompressed(&mut hash_input)?; // copies bytes from salt
        }
        prover_commitment.serialize_uncompressed(&mut hash_input)?; // serializes x, then y, see ec/src/models/twisted_edwards/mod.rs
        hash_input.extend_from_slice(message);

        // Compute the supposed verifier response: e := H(salt || r || msg);
        let digest = bowe_hopwood::CRH::<P, W>::evaluate(&parameters.crh_parameters, hash_input)?;
        end_timer!(verifier_challenge_time);
        Ok(digest)
    }
}

pub struct PoseidonSchnorrAdapter<C: CurveGroup> {
    _c: PhantomData<*const C>,
}

impl<C> SchnorrAdapter for PoseidonSchnorrAdapter<C>
where
    C: CurveGroup + ToConstraintField<C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    type C = C;
    type Input = C::BaseField;
    type CRH = poseidon::CRH<C::BaseField>;

    fn compute_verifier_challenge(
        parameters: &Parameters<Self::C, <Self::CRH as CRHScheme>::Parameters>,
        prover_commitment: &Self::C,
        message: &[Self::Input],
    ) -> Result<<Self::C as CurveGroup>::BaseField, Error> {
        let verifier_challenge_time = start_timer!(|| "Verifier Challenge");
        // Hash everything to get verifier challenge.
        let mut hash_input = Vec::new();

        if let Some(salt) = parameters.salt {
            hash_input.extend_from_slice(&salt.to_field_elements().unwrap());
        }
        hash_input.extend_from_slice(&prover_commitment.to_field_elements().unwrap()); // x and y
        hash_input.extend_from_slice(message);

        // Compute the supposed verifier response: e := H(salt || r || msg);
        let digest =
            poseidon::CRH::<C::BaseField>::evaluate(&parameters.crh_parameters, hash_input)?;
        end_timer!(verifier_challenge_time);
        Ok(digest)
    }
}

pub struct SchnorrSignatureScheme<A: SchnorrAdapter> {
    _a: PhantomData<*const A>,
}

impl<C, A> SignatureScheme for SchnorrSignatureScheme<A>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    A: SchnorrAdapter<C = C>,
{
    type Input = A::Input;
    type Parameters = Parameters<A::C, <A::CRH as CRHScheme>::Parameters>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let setup_time = start_timer!(|| "SchnorrSig::Setup");

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let generator = C::rand(rng).into();
        let crh_parameters = A::CRH::setup(rng)?;

        end_timer!(setup_time);
        Ok(Self::Parameters {
            generator,
            salt: Some(salt),
            crh_parameters,
        })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        let keygen_time = start_timer!(|| "SchnorrSig::KeyGen");

        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        end_timer!(keygen_time);
        Ok((public_key, SecretKey(secret_key)))
    }

    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[Self::Input],
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        let sign_time = start_timer!(|| "SchnorrSig::Sign");
        // (k, e);
        // Sample a random scalar `k` from the prime scalar field.
        let random_scalar: C::ScalarField = C::ScalarField::rand(rng);
        // Commit to the random scalar via r := k · G.
        // This is the prover's first msg in the Sigma protocol.
        let prover_commitment = parameters.generator.mul(random_scalar);

        let verifier_challenge =
            A::compute_verifier_challenge(parameters, &prover_commitment, message)?;

        // k - xe;
        let prover_response = random_scalar
            - (C::ScalarField::from_le_bytes_mod_order(
                &verifier_challenge.into_bigint().to_bytes_le(),
            ) * sk.0);

        let signature = Signature {
            prover_response,
            verifier_challenge,
        };

        end_timer!(sign_time);
        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[Self::Input],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let verify_time = start_timer!(|| "SchnorrSig::Verify");

        let Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = pk.mul_bigint(verifier_challenge.into_bigint());
        claimed_prover_commitment += &public_key_times_verifier_challenge;

        let obtained_verifier_challenge =
            A::compute_verifier_challenge(parameters, &claimed_prover_commitment, message)?;

        end_timer!(verify_time);
        Ok(verifier_challenge == &obtained_verifier_challenge)
    }
}

pub type BHSchnorr<P, W> = SchnorrSignatureScheme<BHSchnorrAdapter<P, W>>;

pub type PoseidonSchnorr<C> = SchnorrSignatureScheme<PoseidonSchnorrAdapter<C>>;

#[cfg(test)]
mod test {
    use crate::signature::schnorr;
    use crate::signature::test::*;
    use ark_crypto_primitives::crh::pedersen;
    use ark_ed_on_bn254::{EdwardsConfig, EdwardsProjective};

    #[derive(Clone)]
    struct Window;
    impl pedersen::Window for Window {
        const WINDOW_SIZE: usize = 63; // this is in bits, make as large as possible
        const NUM_WINDOWS: usize = 8;
    }

    #[test]
    fn bowe_hopwood_schnorr_test() {
        byte_signature_test::<schnorr::BHSchnorr<EdwardsConfig, Window>>()
    }

    #[test]
    fn poseidon_schnorr_test() {
        field_signature_test::<schnorr::PoseidonSchnorr<EdwardsProjective>, _>()
    }
}
