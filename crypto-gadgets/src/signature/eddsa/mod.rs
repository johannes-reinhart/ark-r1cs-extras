use crate::crh::poseidon;
use crate::signature::SignatureScheme;
use ark_crypto_primitives::crh::pedersen::Window;
use ark_crypto_primitives::crh::{bowe_hopwood, CRHScheme};
use ark_crypto_primitives::sponge::Absorb;
use ark_crypto_primitives::Error;
use ark_ec::twisted_edwards::{Projective, TECurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{end_timer, start_timer, UniformRand};
use blake2::Blake2s256 as Blake2s;
use core::marker::PhantomData;
use core::ops::Mul;
use derivative::Derivative;
use digest::Digest;

#[cfg(feature = "r1cs")]
pub mod constraints;

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
    pub prover_commitment: C::Affine,    // uppercase R
}

/// Adapter for EdDSA Signature
///
/// The EdDSA signatures for different hash functions only differ in the computation of
/// the verifier challenge. As the hash function might have different input types,
/// not only the serialization of the message, but also the serialization of the
/// prover commitment and the public key are affected
pub trait EdDSAAdapter {
    type C: CurveGroup;
    type Input: CanonicalSerialize + Clone;
    type CRH: CRHScheme;

    fn compute_verifier_challenge(
        parameters: &Parameters<Self::C, <Self::CRH as CRHScheme>::Parameters>,
        prover_commitment: &Self::C,
        public_key: &Self::C,
        message: &[Self::Input],
    ) -> Result<<Self::C as CurveGroup>::BaseField, Error>;
}

pub struct BHEdDSAAdapter<P: TECurveConfig, W: Window> {
    _p: PhantomData<*const P>,
    _w: PhantomData<*const W>,
}

impl<P, W> EdDSAAdapter for BHEdDSAAdapter<P, W>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
    W: Window,
{
    type C = Projective<P>;
    type Input = u8;
    type CRH = bowe_hopwood::CRH<P, W>;

    fn compute_verifier_challenge(
        parameters: &Parameters<Self::C, <Self::CRH as CRHScheme>::Parameters>,
        prover_commitment: &Self::C,
        public_key: &Self::C,
        message: &[Self::Input],
    ) -> Result<<Self::C as CurveGroup>::BaseField, Error> {
        // Hash everything to get verifier challenge.
        let mut hash_input = Vec::new();

        if let Some(salt) = parameters.salt {
            salt.serialize_uncompressed(&mut hash_input)?; // copies bytes from salt
        }
        prover_commitment.serialize_uncompressed(&mut hash_input)?; // serializes x, then y, see ec/src/models/twisted_edwards/mod.rs
        public_key.serialize_uncompressed(&mut hash_input)?; // serializes x, then y, see ec/src/models/twisted_edwards/mod.rs

        hash_input.extend_from_slice(message);

        // Compute the supposed verifier response: e := H(salt || r || msg);
        let digest = bowe_hopwood::CRH::<P, W>::evaluate(&parameters.crh_parameters, hash_input)?;
        Ok(digest)
    }
}

pub struct PoseidonEdDSAAdapter<C: CurveGroup> {
    _c: PhantomData<*const C>,
}

impl<C> EdDSAAdapter for PoseidonEdDSAAdapter<C>
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
        public_key: &Self::C,
        message: &[Self::Input],
    ) -> Result<<Self::C as CurveGroup>::BaseField, Error> {
        // Hash everything to get verifier challenge.
        let mut hash_input = Vec::new();

        if let Some(salt) = parameters.salt {
            hash_input.extend_from_slice(&salt.to_field_elements().unwrap());
        }
        hash_input.extend_from_slice(&prover_commitment.to_field_elements().unwrap()); // x and y
        hash_input.extend_from_slice(&public_key.to_field_elements().unwrap()); // serializes x, then y, see ec/src/models/twisted_edwards/mod.rs

        hash_input.extend_from_slice(message);

        // Compute the supposed verifier response: e := H(salt || r || msg);
        let digest =
            poseidon::CRH::<C::BaseField>::evaluate(&parameters.crh_parameters, hash_input)?;
        Ok(digest)
    }
}

pub struct EdDSASignatureScheme<A: EdDSAAdapter> {
    _a: PhantomData<*const A>,
}

impl<C, A> SignatureScheme for EdDSASignatureScheme<A>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    A: EdDSAAdapter<C = C>,
{
    type Input = A::Input;
    type Parameters = Parameters<A::C, <A::CRH as CRHScheme>::Parameters>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let setup_time = start_timer!(|| "EdDSASig::Setup");

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
        let keygen_time = start_timer!(|| "EdDSA::KeyGen");

        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        end_timer!(keygen_time);
        Ok((public_key, SecretKey(secret_key)))
    }

    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[Self::Input],
        _rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        let sign_time = start_timer!(|| "EdDSA::Sign");

        let public_key = parameters.generator.mul(sk.0);

        // compute randomizing scalar `r`
        let mut secret_hash_input = Vec::new();
        sk.0.serialize_uncompressed(&mut secret_hash_input)?;
        message.serialize_uncompressed(&mut secret_hash_input)?;
        let random_scalar =
            C::ScalarField::from_le_bytes_mod_order(Blake2s::digest(&secret_hash_input).as_slice());

        // Commit to the random scalar via R := r · B.
        let prover_commitment = parameters.generator.mul(random_scalar);

        let verifier_challenge =
            A::compute_verifier_challenge(parameters, &prover_commitment, &public_key, &message)?;

        // s = r + H(R||A||M) * a
        let prover_response = random_scalar
            + (C::ScalarField::from_le_bytes_mod_order(
                &verifier_challenge.into_bigint().to_bytes_le(),
            ) * sk.0);

        let signature = Signature {
            prover_response,
            prover_commitment: prover_commitment.into(),
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
        let verify_time = start_timer!(|| "EdDSA::Verify");

        let Signature {
            prover_response,
            prover_commitment,
        } = signature;
        // s * B
        let lhs = parameters.generator.mul(*prover_response);
        // R + H(R||A||M) * A
        let h = A::compute_verifier_challenge(
            parameters,
            &prover_commitment.into_group(),
            &pk.into_group(),
            message,
        )?;
        let rhs = pk.mul_bigint(h.into_bigint()) + *prover_commitment;

        end_timer!(verify_time);
        Ok(lhs == rhs)
    }
}

pub type BHEdDSA<P, W> = EdDSASignatureScheme<BHEdDSAAdapter<P, W>>;

pub type PoseidonEdDSA<C> = EdDSASignatureScheme<PoseidonEdDSAAdapter<C>>;

#[cfg(test)]
mod test {
    use crate::signature::eddsa;
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
    fn bowe_hopwood_eddsa_test() {
        byte_signature_test::<eddsa::BHEdDSA<EdwardsConfig, Window>>()
    }

    #[test]
    fn poseidon_eddsa_test() {
        field_signature_test::<eddsa::PoseidonEdDSA<EdwardsProjective>, _>()
    }
}
