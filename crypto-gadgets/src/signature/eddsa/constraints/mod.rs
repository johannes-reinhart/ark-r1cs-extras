use crate::signature::eddsa::{Parameters, PublicKey, Signature};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBytesGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::groups::{CurveVar, GroupOpsBounds};
use ark_r1cs_std::prelude::UInt8;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use core::borrow::Borrow;
use core::marker::PhantomData;
use derivative::Derivative;

pub mod bowe_hopwood;
pub mod poseidon;

type BaseField<C> = <C as CurveGroup>::BaseField;

#[derive(Clone)]
pub struct ParametersVar<C, GC, PVar>
where
    C: CurveGroup,
    BaseField<C>: PrimeField,
    GC: CurveVar<C, BaseField<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
    PVar: Clone,
{
    generator: GC,
    salt: Option<Vec<UInt8<BaseField<C>>>>,
    crh_parameters: PVar,
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, GC: CurveVar<C, BaseField<C>>"),
    Clone(bound = "C: CurveGroup, GC: CurveVar<C, BaseField<C>>")
)]
pub struct PublicKeyVar<C, GC>
where
    C: CurveGroup,
    BaseField<C>: PrimeField,
    GC: CurveVar<C, BaseField<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    pub_key: GC,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, GC: CurveVar<C, BaseField<C>>"),
    Clone(bound = "C: CurveGroup, GC: CurveVar<C, BaseField<C>>")
)]
pub struct SignatureVar<C, GC>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    GC: CurveVar<C, BaseField<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    prover_response: Vec<Boolean<BaseField<C>>>,
    prover_commitment: GC,
    #[doc(hidden)]
    _group: PhantomData<*const GC>,
}

impl<C, GC, P, PVar> AllocVar<Parameters<C, P>, BaseField<C>> for ParametersVar<C, GC, PVar>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    GC: CurveVar<C, BaseField<C>>,
    P: Clone + CanonicalSerialize + CanonicalDeserialize + Sync,
    PVar: Clone + AllocVar<P, BaseField<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Parameters<C, P>>>(
        cs: impl Into<Namespace<BaseField<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let generator = GC::new_variable(cs.clone(), || Ok(val.borrow().generator), mode)?;
            let crh_parameters =
                PVar::new_variable(cs.clone(), || Ok(val.borrow().crh_parameters.clone()), mode)?;
            let native_salt = val.borrow().salt;
            let mut constraint_salt = Vec::<UInt8<BaseField<C>>>::new();

            match native_salt {
                Some(native_salt) => {
                    for i in 0..32 {
                        constraint_salt.push(UInt8::<BaseField<C>>::new_variable(
                            cs.clone(),
                            || Ok(native_salt[i]),
                            mode,
                        )?);
                    }

                    return Ok(Self {
                        generator,
                        salt: Some(constraint_salt),
                        crh_parameters,
                        _curve: PhantomData,
                    });
                },
                None => Ok(Self {
                    generator,
                    salt: None,
                    crh_parameters,
                    _curve: PhantomData,
                }),
            }
        })
    }
}

impl<C, GC> AllocVar<PublicKey<C>, BaseField<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    GC: CurveVar<C, BaseField<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<BaseField<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = GC::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

impl<C, GC> AllocVar<Signature<C>, BaseField<C>> for SignatureVar<C, GC>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    GC: CurveVar<C, BaseField<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<BaseField<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let response_bits = val.borrow().prover_response.into_bigint().to_bits_le();
            let mut prover_response = Vec::<Boolean<BaseField<C>>>::new();
            for bit in response_bits
                .iter()
                .take(C::ScalarField::MODULUS_BIT_SIZE as usize)
            {
                prover_response.push(Boolean::<BaseField<C>>::new_variable(
                    cs.clone(),
                    || Ok(bit),
                    mode,
                )?);
            }
            let prover_commitment =
                GC::new_variable(cs.clone(), || Ok(val.borrow().prover_commitment), mode)?;

            Ok(SignatureVar {
                prover_response,
                prover_commitment,
                _group: PhantomData,
            })
        })
    }
}

impl<C, GC> EqGadget<BaseField<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    GC: CurveVar<C, BaseField<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<BaseField<C>>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<BaseField<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<BaseField<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl<C, GC> ToBytesGadget<BaseField<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    C::BaseField: PrimeField,
    GC: CurveVar<C, BaseField<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn to_bytes_le(&self) -> Result<Vec<UInt8<BaseField<C>>>, SynthesisError> {
        self.pub_key.to_bytes_le()
    }
}
