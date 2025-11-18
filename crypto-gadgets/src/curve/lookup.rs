use ark_ec::twisted_edwards::{Affine, MontgomeryAffine, TECurveConfig};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::{AllocatedFp, FpVar};
use ark_r1cs_std::groups::curves::twisted_edwards::{AffineVar, MontgomeryAffineVar};
use ark_r1cs_std::prelude::*;
use ark_relations::lc;
use ark_relations::r1cs::{SynthesisError, Variable};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

/// Performs a lookup in a 8-element table using 3 bits.
pub trait ThreeBitLookupGadget<ConstraintF: Field>: Sized {
    /// The type of values being looked up.
    type TableConstant;

    /// Interprets the slice `bits` as a three-bit integer `b = bits[0] + (bits[1]
    /// << 1) + (bits[2] << 2)`, and then outputs `constants[b]`.
    ///
    /// For example, if `bits == [0, 1, 0]`, and `constants == [0, 1, 2, 3, 4, 5, 6, 7, 8]`, this
    /// method should output a variable corresponding to `2`.
    ///
    /// # Panics
    ///
    /// This method panics if `bits.len() != 3` or `constants.len() != 8`.
    fn three_bit_lookup(
        bits: &[Boolean<ConstraintF>],
        constants: &[Self::TableConstant],
    ) -> Result<Self, SynthesisError>;
}

// /// Uses three bits to perform a lookup into a table
// /// `b` is little-endian: `b[0]` is LSB.
// impl<F: PrimeField, const N: usize> ThreeBitLookupGadget<F> for [AllocatedFp<F>; N] {
//     type TableConstant = [F; N];
//     #[tracing::instrument(target = "r1cs")]
//     fn three_bit_lookup(b: &[Boolean<F>], c: &[Self::TableConstant]) -> Result<Self, SynthesisError> {
//         debug_assert_eq!(b.len(), 3);
//         debug_assert_eq!(c.len(), 8);
//         let mut result = Vec::with_capacity(N);
//
//         for i in 0..N {
//             result.push(
//                 AllocatedFp::new_witness(b.cs(), || {
//                     let b0 = usize::from(b[0].value()?);
//                     let b1 = usize::from(b[1].value()?);
//                     let b2 = usize::from(b[2].value()?);
//                     let index = b0 + (b1 << 1) + (b2 << 2);
//                     Ok(c[index][i])
//                 })?);
//         }
//
//         let b01 = &b[0] & &b[1];
//         let b02 = &b[0] & &b[2];
//         let b12 = &b[1] & &b[2];
//         let b012 = &b01 & &b[2];
//         let one = Variable::One;
//         for i in 0..N {
//             b.cs().enforce_constraint(
//                 // All bits off
//                 ((lc!() + one) * c[0][i]) +
//
//                 // Bit 0 is on
//                 (b[0].lc() * -c[0][i]) +
//                 (b[0].lc() * c[1][i]) +
//
//                 // Bit 1 is on
//                 (b[1].lc() * -c[0][i]) +
//                 (b[1].lc() * c[2][i]) +
//
//                 // Bit 0 and 1 are on
//                 (b01.lc() * (-c[1][i] + -c[2][i] + c[0][i] + c[3][i])) +
//
//                 // Bit 2 is on
//                 (b[2].lc() * (-c[0][i] + c[4][i])) +
//
//                 // Bit 0 and 2 are on
//                 (b02.lc() * (c[0][i] - c[1][i] -c[4][i] + c[5][i])) +
//
//                 // Bit 1 and 2 are on
//                 (b12.lc() * (c[0][i] - c[2][i] - c[4][i] + c[6][i])) +
//
//                 // Bits 0, 1 and 2 are on
//                 (b012.lc() * (-c[0][i] + c[1][i] + c[2][i] - c[3][i] + c[4][i] - c[5][i] -c[6][i] + c[7][i])),
//                 lc!() + one,
//                 lc!() + result[i].variable,
//             )?;
//         }
//         Ok(result.try_into().unwrap())
//     }
// }

/// Uses three bits to perform a lookup into a table
/// `b` is little-endian: `b[0]` is LSB.
impl<F: PrimeField, const N: usize> ThreeBitLookupGadget<F> for [AllocatedFp<F>; N] {
    type TableConstant = [F; N];
    #[tracing::instrument(target = "r1cs")]
    fn three_bit_lookup(
        b: &[Boolean<F>],
        c: &[Self::TableConstant],
    ) -> Result<Self, SynthesisError> {
        debug_assert_eq!(b.len(), 3);
        debug_assert_eq!(c.len(), 8);
        let mut result = Vec::with_capacity(N);

        for i in 0..N {
            result.push(AllocatedFp::new_witness(b.cs(), || {
                let b0 = usize::from(b[0].value()?);
                let b1 = usize::from(b[1].value()?);
                let b2 = usize::from(b[2].value()?);
                let index = b0 + (b1 << 1) + (b2 << 2);
                Ok(c[index][i])
            })?);
        }

        let b12 = &b[1] & &b[2];
        let one = Variable::One;
        for i in 0..N {
            b.cs().enforce_constraint(
                b[0].lc(),
                (lc!() + one) * (-c[0][i] + c[1][i])
                    + b[1].lc() * (c[0][i] - c[2][i] - c[1][i] + c[3][i])
                    + b[2].lc() * (c[0][i] - c[4][i] - c[1][i] + c[5][i])
                    + b12.lc()
                        * (-c[0][i] + c[2][i] + c[4][i] - c[6][i] + c[1][i] - c[3][i] - c[5][i]
                            + c[7][i]),
                (lc!() + result[i].variable) - (lc!() + one) * c[0][i]
                    + b[1].lc() * (c[0][i] - c[2][i])
                    + b[2].lc() * (c[0][i] - c[4][i])
                    + b12.lc() * (-c[0][i] + c[2][i] + c[4][i] - c[6][i]),
            )?;
        }
        Ok(result.try_into().unwrap())
    }
}

impl<F: PrimeField> ThreeBitLookupGadget<F> for FpVar<F> {
    type TableConstant = F;

    #[tracing::instrument(target = "r1cs")]
    fn three_bit_lookup(
        b: &[Boolean<F>],
        c: &[Self::TableConstant],
    ) -> Result<Self, SynthesisError> {
        debug_assert_eq!(b.len(), 3);
        debug_assert_eq!(c.len(), 8);

        if b.is_constant() {
            let b0 = usize::from(b[0].value()?);
            let b1 = usize::from(b[1].value()?);
            let b2 = usize::from(b[2].value()?);
            let index = b0 + (b1 << 1) + (b2 << 2);
            Ok(Self::Constant(c[index]))
        } else {
            let c_arr: Vec<[F; 1]> = c.iter().map(|&x| [x]).collect();
            let arr = <[AllocatedFp<F>; 1]>::three_bit_lookup(b, &c_arr)?;
            Ok(Self::Var(arr[0].clone()))
        }
    }
}

/// Uses three bits to perform a lookup into a table
/// `b` is little-endian: `b[0]` is LSB.
impl<P> ThreeBitLookupGadget<P::BaseField> for MontgomeryAffineVar<P, FpVar<P::BaseField>>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    type TableConstant = MontgomeryAffine<P::MontCurveConfig>;

    #[tracing::instrument(target = "r1cs")]
    fn three_bit_lookup(
        b: &[Boolean<P::BaseField>],
        c: &[Self::TableConstant],
    ) -> Result<Self, SynthesisError> {
        debug_assert_eq!(b.len(), 3);
        debug_assert_eq!(c.len(), 8);

        if b.is_constant() {
            let b0 = usize::from(b[0].value()?);
            let b1 = usize::from(b[1].value()?);
            let b2 = usize::from(b[2].value()?);
            let index = b0 + (b1 << 1) + (b2 << 2);
            let pt = c[index];
            Ok(Self::new(FpVar::Constant(pt.x), FpVar::Constant(pt.y)))
        } else {
            let c_arr: Vec<_> = c.iter().map(|&pt| [pt.x, pt.y]).collect();
            let arr = <[AllocatedFp<_>; 2]>::three_bit_lookup(b, &c_arr)?;
            Ok(Self::new(
                FpVar::Var(arr[0].clone()),
                FpVar::Var(arr[1].clone()),
            ))
        }
    }
}

/// Uses three bits to perform a lookup into a table
/// `b` is little-endian: `b[0]` is LSB.
impl<P> ThreeBitLookupGadget<P::BaseField> for AffineVar<P, FpVar<P::BaseField>>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    type TableConstant = Affine<P>;

    #[tracing::instrument(target = "r1cs")]
    fn three_bit_lookup(
        b: &[Boolean<P::BaseField>],
        c: &[Self::TableConstant],
    ) -> Result<Self, SynthesisError> {
        debug_assert_eq!(b.len(), 3);
        debug_assert_eq!(c.len(), 8);

        if b.is_constant() {
            let b0 = usize::from(b[0].value()?);
            let b1 = usize::from(b[1].value()?);
            let b2 = usize::from(b[2].value()?);
            let index = b0 + (b1 << 1) + (b2 << 2);
            let pt = c[index];
            Ok(Self::new(FpVar::Constant(pt.x), FpVar::Constant(pt.y)))
        } else {
            let c_arr: Vec<_> = c.iter().map(|&pt| [pt.x, pt.y]).collect();
            let arr = <[AllocatedFp<_>; 2]>::three_bit_lookup(b, &c_arr)?;
            Ok(Self::new(
                FpVar::Var(arr[0].clone()),
                FpVar::Var(arr[1].clone()),
            ))
        }
    }
}
