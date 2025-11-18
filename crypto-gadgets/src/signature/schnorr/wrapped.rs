use crate::signature::SignatureScheme;
use ark_crypto_primitives::signature::{
    schnorr as ark_schnorr, SignatureScheme as ArkSignatureScheme,
};
use ark_crypto_primitives::Error;
use ark_ec::CurveGroup;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use ark_std::fmt::Debug;
use ark_std::hash::Hash;
use ark_std::io::{Read, Write};
use ark_std::rand;
use ark_std::rand::{Rng, RngCore};
use ark_std::vec::Vec;
use digest::Digest;

// Fake Rng for initializing schnorr::Parameters. This is used for serialization, to construct
// a schnorr::Parameters object. Unfortunately, schnorr::Parameters
// has a private field _hash, and the only way to get a Parameter object is to call
// the setup function, which requires a Rng object. The actual parameters will be overwritten,
// after object initialization, therefore, this is ok. Do not
// use for anything else
struct ZeroRng;

impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = 0;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(self.fill_bytes(dest))
    }
}

pub struct Schnorr<C: CurveGroup, D: Digest>(ark_schnorr::Schnorr<C, D>);

#[derive(Clone, Debug)]
pub struct Parameters<C: CurveGroup, D: Digest + Send + Sync>(ark_schnorr::Parameters<C, D>);

#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<C: CurveGroup + Hash>(ark_schnorr::PublicKey<C>);

#[derive(Clone, Debug, CanonicalSerialize, Default)]
pub struct SecretKey<C: CurveGroup>(ark_schnorr::SecretKey<C>);

#[derive(Clone, Debug, Default)]
pub struct Signature<C: CurveGroup>(ark_schnorr::Signature<C>);

impl<C: CurveGroup + Hash, D: Digest + Send + Sync> CanonicalSerialize for Parameters<C, D> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0
            .generator
            .serialize_with_mode(&mut writer, compress)?;
        self.0.salt.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.generator.serialized_size(compress) + self.0.salt.serialized_size(compress)
    }
}

impl<C: CurveGroup + Hash, D: Digest + Send + Sync> Valid for Parameters<C, D> {
    fn check(&self) -> Result<(), SerializationError> {
        self.0.generator.check()?;
        self.0.salt.check()?;
        Ok(())
    }
}

impl<C: CurveGroup + Hash, D: Digest + Send + Sync> CanonicalDeserialize for Parameters<C, D> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let generator = C::Affine::deserialize_with_mode(&mut reader, compress, validate)?;
        let salt = <[u8; 32]>::deserialize_with_mode(&mut reader, compress, validate)?;
        let mut parameters = ark_schnorr::Schnorr::setup(&mut ZeroRng {}).unwrap();
        parameters.generator = generator;
        parameters.salt = salt;
        Ok(Parameters(parameters))
    }
}

impl<C: CurveGroup + Hash, D: Digest + Send + Sync> PartialEq for Parameters<C, D> {
    fn eq(&self, other: &Self) -> bool {
        self.0.generator == other.0.generator && self.0.salt == other.0.salt
    }
}

impl<C: CurveGroup> Valid for SecretKey<C> {
    fn check(&self) -> Result<(), SerializationError> {
        self.0 .0.check()
    }
}

impl<C: CurveGroup> CanonicalDeserialize for SecretKey<C> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let key = C::ScalarField::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(SecretKey(ark_schnorr::SecretKey(key)))
    }
}

impl<C: CurveGroup> PartialEq for SecretKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0 .0 == other.0 .0
    }
}

impl<C: CurveGroup> CanonicalSerialize for Signature<C> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0
            .prover_response
            .serialize_with_mode(&mut writer, compress)?;
        self.0
            .verifier_challenge
            .serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.prover_response.serialized_size(compress)
            + self.0.verifier_challenge.serialized_size(compress)
    }
}

impl<C: CurveGroup> Valid for Signature<C> {
    fn check(&self) -> Result<(), SerializationError> {
        self.0.prover_response.check()?;
        self.0.verifier_challenge.check()?;
        Ok(())
    }
}

impl<C: CurveGroup> CanonicalDeserialize for Signature<C> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let prover_response =
            C::ScalarField::deserialize_with_mode(&mut reader, compress, validate)?;
        let verifier_challenge =
            C::ScalarField::deserialize_with_mode(&mut reader, compress, validate)?;
        let signature = ark_schnorr::Signature {
            prover_response,
            verifier_challenge,
        };
        Ok(Signature(signature))
    }
}

impl<C: CurveGroup> PartialEq for Signature<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0.prover_response == other.0.prover_response
            && self.0.verifier_challenge == other.0.verifier_challenge
    }
}

impl<C: CurveGroup + Hash, D: Digest + Send + Sync + Debug + Clone> SignatureScheme
    for Schnorr<C, D>
{
    type Input = u8;
    type Parameters = Parameters<C, D>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    #[inline]
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        ark_schnorr::Schnorr::<C, D>::setup(rng).map(|p| Parameters(p))
    }

    #[inline]
    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        ark_schnorr::Schnorr::<C, D>::keygen(&pp.0, rng)
            .map(|(pk, sk)| (PublicKey(pk), SecretKey(sk)))
    }

    #[inline]
    fn sign<R: Rng>(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        ark_schnorr::Schnorr::<C, D>::sign(&pp.0, &sk.0, message, rng).map(|s| Signature(s))
    }

    #[inline]
    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        ark_schnorr::Schnorr::<C, D>::verify(&pp.0, &pk.0, message, &signature.0)
    }
}

#[cfg(test)]
mod test {
    use crate::signature::schnorr;
    use crate::signature::test::*;
    use ark_ed_on_bn254::EdwardsProjective;
    use blake2::Blake2s256 as Blake2s;

    #[test]
    fn wrapped_schnorr_test() {
        byte_signature_test::<schnorr::wrapped::Schnorr<EdwardsProjective, Blake2s>>()
    }
}
