//! SNARK-friendly signature schemes
//!
//! Includes EdDSA and Schnorr signature schemes with either Bowe-Hopwood (Pedersen-Style) or Poseidon SNARK-friendly hashes
//!
//! Schnorr Signature is adapted from ark-crypto-primitives with following changes:
//! - provides CanonicalSerialize/CanonicalDeserialize for all types for easier deployment
//! - reduced constraint count through optimized fixed-base scalar multiplication

use ark_crypto_primitives::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt::Debug;
use ark_std::hash::Hash;
use ark_std::rand::Rng;

pub mod eddsa;
pub mod schnorr;

#[cfg(feature = "r1cs")]
pub mod constraints;

/// Signature scheme with types that implement CanonicalSerialize and CanonicalDeserialize
pub trait SignatureScheme {
    type Input: Clone;
    type Parameters: Clone + Sync + CanonicalSerialize + CanonicalDeserialize;
    type PublicKey: Clone
        + Debug
        + PartialEq
        + Send
        + Sync
        + CanonicalSerialize
        + CanonicalDeserialize
        + Hash
        + Eq;
    type SecretKey: Clone
        + Debug
        + PartialEq
        + Send
        + Sync
        + CanonicalSerialize
        + CanonicalDeserialize
        + Default;
    type Signature: Clone
        + Debug
        + PartialEq
        + Send
        + Sync
        + CanonicalSerialize
        + CanonicalDeserialize
        + Default;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn sign<R: Rng>(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[Self::Input],
        rng: &mut R,
    ) -> Result<Self::Signature, Error>;

    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[Self::Input],
        signature: &Self::Signature,
    ) -> Result<bool, Error>;
}

#[cfg(test)]
mod test {
    use crate::signature::*;
    use ark_ed_on_bn254::EdwardsProjective;
    use ark_ff::{PrimeField, ToConstraintField};
    use ark_std::test_rng;
    use blake2::Blake2s256 as Blake2s;

    fn reserialize<T>(value: T) -> T
    where
        T: CanonicalSerialize + CanonicalDeserialize,
    {
        let mut buf_compressed = Vec::new();
        let mut buf_uncompressed = Vec::new();
        value.serialize_compressed(&mut buf_compressed).unwrap();
        value.serialize_uncompressed(&mut buf_uncompressed).unwrap();

        let value2 = T::deserialize_compressed(buf_compressed.as_slice()).unwrap();
        //let value3 = T::deserialize_uncompressed(buf_uncompressed.as_slice()).unwrap();

        //assert_eq!(value, value2);
        //assert_eq!(value, value3);

        value2
    }

    fn sign_and_verify<S: SignatureScheme>(message: &[S::Input]) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();

        let parameters = reserialize(parameters);
        let pk = reserialize(pk);
        let sk = reserialize(sk);

        let sig = S::sign(&parameters, &sk, &message, rng).unwrap();

        let sig = reserialize(sig);

        assert!(S::verify(&parameters, &pk, &message, &sig).unwrap());
    }

    fn failed_verification<S: SignatureScheme>(message: &[S::Input], bad_message: &[S::Input]) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(!S::verify(&parameters, &pk, bad_message, &sig).unwrap());
    }

    pub(crate) fn byte_signature_test<S>()
    where
        S: SignatureScheme<Input = u8>,
    {
        let message = "Hi, I am a signature!";
        sign_and_verify::<S>(message.as_bytes());
        failed_verification::<schnorr::wrapped::Schnorr<EdwardsProjective, Blake2s>>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );
    }

    pub(crate) fn field_signature_test<S, F: PrimeField>()
    where
        S: SignatureScheme<Input = F>,
    {
        let message = "Hi, I am a signature!";
        let message = message.as_bytes().to_field_elements().unwrap();
        sign_and_verify::<S>(&message);

        let bad_message = "Bad message".as_bytes().to_field_elements().unwrap();
        failed_verification::<S>(&message, &bad_message);
    }
}
