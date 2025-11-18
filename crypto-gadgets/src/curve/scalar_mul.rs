use crate::curve::convert::edwards_to_montgomery;
use crate::curve::lookup::ThreeBitLookupGadget;
use ark_ec::twisted_edwards::{Affine, MontgomeryAffine, Projective, TECurveConfig};
use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_ff::{Field, PrimeField, Zero};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::{AffineVar, MontgomeryAffineVar};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use ark_std::vec::Vec;
use core::cmp::min;
use derivative::Derivative;

type BasePrimeField<P> = <<P as CurveConfig>::BaseField as Field>::BasePrimeField;

const WINDOW_SIZE_BITS: usize = 3;
const WINDOW_SIZE_ITEMS: usize = 1 << WINDOW_SIZE_BITS;

/// Super efficient scalar multiplication for a fixed base
/// Uses 3-bit windows and does (incomplete) addition mostly in affine montgomery coordinates
#[tracing::instrument(target = "r1cs")]
pub fn scalar_mul_le_fixed_base<P>(
    base: Projective<P>,
    bits: &[Boolean<BasePrimeField<P>>],
) -> Result<AffineVar<P, FpVar<P::BaseField>>, SynthesisError>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    // pad bits with zeros
    let mut bits = bits.to_vec();
    while bits.len() % WINDOW_SIZE_BITS != 0 {
        bits.push(Boolean::FALSE);
    }

    let n_windows = bits.len() / WINDOW_SIZE_BITS;
    // ensure, that the sum with (incomplete) montgomery addition does not wrap around
    let n_windows_mg = min(
        n_windows,
        P::ScalarField::MODULUS_BIT_SIZE as usize / WINDOW_SIZE_BITS - 1,
    );

    let mut current = base.clone();
    let mut start = base.clone();
    let mut accumulated_offset = Projective::<P>::zero();

    let bit_chunks = bits.chunks(WINDOW_SIZE_BITS);
    let mut selected_pts_mg = Vec::with_capacity(n_windows_mg);
    let mut selected_pts_ed = Vec::with_capacity(n_windows - n_windows_mg);
    // Precompute lookup tables
    for (i, bit_chunk) in bit_chunks.enumerate() {
        // For each window, generate 8 points, in little endian:
        // (0,0,0) = 0 = 0
        // (1,0,0) = 1 = start 		# add
        // (0,1,0) = 2 = start+start	# double
        // (1,1,0) = 3 = 2+start 		# double and add
        // (0,0,1) = 4 = ...
        // (1,0,1) = 5 =
        // (0,1,1) = 6 =
        // (1,1,1) = 7 =
        let mut pts = Vec::with_capacity(WINDOW_SIZE_ITEMS);
        pts.push(Projective::<P>::zero());
        for _j in 1..WINDOW_SIZE_ITEMS {
            pts.push(current);
            current += &start;
        }

        // Offset points by last point in window to avoid adding 0 (as montgomery addition is incomplete)
        let offset = pts.last().unwrap().clone();
        // collect offset to be subtracted in the end
        accumulated_offset += offset;
        for pt in &mut pts {
            *pt += offset;
        }

        if i < n_windows_mg {
            // add points in montgomery affine coordinates
            let table: Vec<_> = pts
                .into_iter()
                .map(|p| {
                    edwards_to_montgomery(p.into_affine())
                        .map_err(|_| SynthesisError::UnexpectedIdentity)
                })
                .collect::<Result<_, _>>()?;
            selected_pts_mg.push(MontgomeryAffineVar::three_bit_lookup(bit_chunk, &table)?);
        } else {
            // add points in edwards affine coordinates
            let table: Vec<_> = pts.into_iter().map(|p| p.into_affine()).collect();
            selected_pts_ed.push(AffineVar::three_bit_lookup(bit_chunk, &table)?);
        }
        start = current;
    }

    // sum up points
    let sum_mg = selected_pts_mg
        .into_iter()
        .reduce(|a, b| a + &b)
        .ok_or(SynthesisError::UnexpectedIdentity)?;

    let sum_ed = selected_pts_ed
        .into_iter()
        .reduce(|a, b| a + &b)
        .ok_or(SynthesisError::UnexpectedIdentity)?;

    // subtract accumulated offset
    let result = sum_mg.into_edwards()? + sum_ed - accumulated_offset;

    Ok(result)
}

/// Scalar multiplication gadget
/// similar to scalar_mul_le_fixed_base
/// caches lookup tables for faster computation of assignment
#[derive(Derivative)]
#[derivative(Clone(bound = "P: TECurveConfig"))]
pub struct FixedBaseScalarMultiplicationCircuit<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    max_bits: usize,
    lookup_tables_mg: Vec<Vec<MontgomeryAffine<P::MontCurveConfig>>>,
    lookup_tables_ed: Vec<Vec<Affine<P>>>,
    accumulated_offset: Projective<P>,
}

impl<P> FixedBaseScalarMultiplicationCircuit<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    pub fn new(base: Projective<P>, mut num_bits: usize) -> Self {
        // extend bits to fill windows
        num_bits = ((num_bits + WINDOW_SIZE_BITS - 1) / WINDOW_SIZE_BITS) * WINDOW_SIZE_BITS;

        let n_windows = num_bits / WINDOW_SIZE_BITS;
        // ensure, that the sum with (incomplete) montgomery addition does not wrap around
        let n_windows_mg = min(
            n_windows,
            P::ScalarField::MODULUS_BIT_SIZE as usize / WINDOW_SIZE_BITS - 1,
        );

        let mut current = base.clone();
        let mut start = base.clone();
        let mut accumulated_offset = Projective::<P>::zero();

        let mut lookup_tables_mg = Vec::with_capacity(n_windows_mg);
        let mut lookup_tables_ed = Vec::with_capacity(n_windows - n_windows_mg);
        // Precompute lookup tables
        for i in 0..n_windows {
            // For each window, generate 8 points, in little endian:
            // (0,0,0) = 0 = 0
            // (1,0,0) = 1 = start 		# add
            // (0,1,0) = 2 = start+start	# double
            // (1,1,0) = 3 = 2+start 		# double and add
            // (0,0,1) = 4 = ...
            // (1,0,1) = 5 =
            // (0,1,1) = 6 =
            // (1,1,1) = 7 =
            let mut pts = Vec::with_capacity(WINDOW_SIZE_ITEMS);
            pts.push(Projective::<P>::zero());
            for _j in 1..WINDOW_SIZE_ITEMS {
                pts.push(current);
                current += &start;
            }

            // Offset points by last point in window to avoid adding 0 (as montgomery addition is incomplete)
            let offset = pts.last().unwrap().clone();
            // collect offset to be subtracted in the end
            accumulated_offset += offset;
            for pt in &mut pts {
                *pt += offset;
            }

            if i < n_windows_mg {
                // add points in montgomery affine coordinates
                let table: Vec<_> = pts
                    .into_iter()
                    .map(|p| edwards_to_montgomery(p.into_affine()).unwrap())
                    .collect();
                lookup_tables_mg.push(table);
            } else {
                // add points in edwards affine coordinates
                let table: Vec<_> = pts.into_iter().map(|p| p.into_affine()).collect();
                lookup_tables_ed.push(table);
            }
            start = current;
        }

        Self {
            max_bits: num_bits,
            lookup_tables_mg,
            lookup_tables_ed,
            accumulated_offset,
        }
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn generate_constraints(
        &self,
        bits: &[Boolean<BasePrimeField<P>>],
    ) -> Result<AffineVar<P, FpVar<P::BaseField>>, SynthesisError> {
        // pad bits with zeros
        let mut bits = bits.to_vec();
        assert!(bits.len() <= self.max_bits);

        while bits.len() != self.max_bits {
            bits.push(Boolean::FALSE);
        }
        let bit_chunks = bits.chunks(WINDOW_SIZE_BITS);

        // Collect montgomery results first, handling the Result wrapper
        let mg_results: Result<Vec<_>, _> = self
            .lookup_tables_mg
            .iter()
            .zip(bit_chunks.clone())
            .map(|(table, bit_chunk)| MontgomeryAffineVar::three_bit_lookup(bit_chunk, table))
            .collect();

        let sum_mg = mg_results?
            .into_iter()
            .reduce(|a, b| a + &b)
            .ok_or(SynthesisError::UnexpectedIdentity)?;

        // Collect edwards results for remaining chunks
        let remaining_chunks = bit_chunks.skip(self.lookup_tables_mg.len());
        let ed_results: Result<Vec<_>, _> = self
            .lookup_tables_ed
            .iter()
            .zip(remaining_chunks)
            .map(|(table, bit_chunk)| AffineVar::three_bit_lookup(bit_chunk, table))
            .collect();

        let sum_ed = ed_results?
            .into_iter()
            .reduce(|a, b| a + &b)
            .ok_or(SynthesisError::UnexpectedIdentity)?;

        // subtract accumulated offset
        let result = sum_mg.into_edwards()? + sum_ed - self.accumulated_offset;

        Ok(result)
    }
}

/// Scalar multiplication
/// Selects between most efficient algorithm for scalar multiplication (depending on whether base
/// is constant or variable)
#[tracing::instrument(target = "r1cs")]
pub fn scalar_mul_le<P>(
    base: &AffineVar<P, FpVar<P::BaseField>>,
    bits: &[Boolean<BasePrimeField<P>>],
) -> Result<AffineVar<P, FpVar<P::BaseField>>, SynthesisError>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    match (&base.x, &base.y) {
        (FpVar::Constant(x), FpVar::Constant(y)) => {
            scalar_mul_le_fixed_base(Affine::new(x.clone(), y.clone()).into_group(), bits)
        },
        _ => base.scalar_mul_le(bits.iter()),
    }
}

#[cfg(test)]
mod test {
    use crate::curve::scalar_mul::{
        scalar_mul_le_fixed_base, FixedBaseScalarMultiplicationCircuit,
    };
    use ark_ec::twisted_edwards::{Projective, TECurveConfig};
    use ark_ed_on_bn254::EdwardsConfig;
    use ark_ff::{BitIteratorLE, PrimeField};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand};
    use std::ops::Mul;

    fn check_scalar_mul<P>(base: Projective<P>, scalar: P::ScalarField)
    where
        P: TECurveConfig,
        P::BaseField: PrimeField,
    {
        let cs = ConstraintSystem::<P::BaseField>::new_ref();

        let scalar_bits: Vec<_> = BitIteratorLE::new(scalar.into_bigint()).collect();
        let scalar_bits_var = Vec::new_witness(cs.clone(), || Ok(scalar_bits)).unwrap();

        let result_var = scalar_mul_le_fixed_base(base, &scalar_bits_var).unwrap();

        let expected_result = base.mul(scalar);
        let expected_result_var: AffineVar<P, FpVar<P::BaseField>> =
            <AffineVar<_, _> as AllocVar<Projective<P>, _>>::new_constant(
                cs.clone(),
                &expected_result,
            )
            .unwrap();
        result_var.enforce_equal(&expected_result_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    fn check_scalar_mul_circuit<P>(base: Projective<P>, scalar: P::ScalarField)
    where
        P: TECurveConfig,
        P::BaseField: PrimeField,
    {
        let cs = ConstraintSystem::<P::BaseField>::new_ref();

        let scalar_bits: Vec<_> = BitIteratorLE::new(scalar.into_bigint()).collect();
        let scalar_bits_var = Vec::new_witness(cs.clone(), || Ok(scalar_bits)).unwrap();

        let scalar_mul_circuit =
            FixedBaseScalarMultiplicationCircuit::new(base, scalar_bits_var.len());
        let result_var = scalar_mul_circuit
            .generate_constraints(&scalar_bits_var)
            .unwrap();

        let expected_result = base.mul(scalar);
        let expected_result_var: AffineVar<P, FpVar<P::BaseField>> =
            <AffineVar<_, _> as AllocVar<Projective<P>, _>>::new_constant(
                cs.clone(),
                &expected_result,
            )
            .unwrap();
        result_var.enforce_equal(&expected_result_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    fn check_scalar_mul_incorrect<P>(base: Projective<P>, scalar: P::ScalarField)
    where
        P: TECurveConfig,
        P::BaseField: PrimeField,
    {
        let cs = ConstraintSystem::<P::BaseField>::new_ref();

        let scalar_bits: Vec<_> = BitIteratorLE::new(scalar.into_bigint()).collect();
        let scalar_bits_var = Vec::new_witness(cs.clone(), || Ok(scalar_bits)).unwrap();

        let result_var = scalar_mul_le_fixed_base(base, &scalar_bits_var).unwrap();

        let expected_result = base.mul(scalar);
        let unexpected_result = expected_result.mul(P::ScalarField::from(3));
        let unexpected_result_var: AffineVar<P, FpVar<P::BaseField>> =
            <AffineVar<_, _> as AllocVar<Projective<P>, _>>::new_constant(
                cs.clone(),
                &unexpected_result,
            )
            .unwrap();
        result_var.enforce_equal(&unexpected_result_var).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    fn check_scalar_mul_circuit_incorrect<P>(base: Projective<P>, scalar: P::ScalarField)
    where
        P: TECurveConfig,
        P::BaseField: PrimeField,
    {
        let cs = ConstraintSystem::<P::BaseField>::new_ref();

        let scalar_bits: Vec<_> = BitIteratorLE::new(scalar.into_bigint()).collect();
        let scalar_bits_var = Vec::new_witness(cs.clone(), || Ok(scalar_bits)).unwrap();

        let scalar_mul_circuit =
            FixedBaseScalarMultiplicationCircuit::new(base, scalar_bits_var.len());
        let result_var = scalar_mul_circuit
            .generate_constraints(&scalar_bits_var)
            .unwrap();

        let expected_result = base.mul(scalar);
        let unexpected_result = expected_result.mul(P::ScalarField::from(3));
        let unexpected_result_var: AffineVar<P, FpVar<P::BaseField>> =
            <AffineVar<_, _> as AllocVar<Projective<P>, _>>::new_constant(
                cs.clone(),
                &unexpected_result,
            )
            .unwrap();
        result_var.enforce_equal(&unexpected_result_var).unwrap();

        assert!(!cs.is_satisfied().unwrap());
    }

    fn compare_scalar_mul_fixed_and_variable<P>(samples: usize)
    where
        P: TECurveConfig,
        P::BaseField: PrimeField,
    {
        let mut rng = &mut test_rng();
        for _s in 0..samples {
            let base = Projective::<P>::rand(&mut rng);
            let scalar = P::ScalarField::rand(&mut rng);
            check_scalar_mul(base, scalar);
            check_scalar_mul_incorrect(base, scalar);
        }
    }

    fn compare_scalar_mul_circuit<P>(samples: usize)
    where
        P: TECurveConfig,
        P::BaseField: PrimeField,
    {
        let mut rng = &mut test_rng();
        for _s in 0..samples {
            let base = Projective::<P>::rand(&mut rng);
            let scalar = P::ScalarField::rand(&mut rng);
            check_scalar_mul_circuit(base, scalar);
            check_scalar_mul_circuit_incorrect(base, scalar);
        }
    }

    #[test]
    fn test_scalar_mul_le() {
        compare_scalar_mul_fixed_and_variable::<EdwardsConfig>(10)
    }

    #[test]
    fn test_scalar_mul_le_circuit() {
        compare_scalar_mul_circuit::<EdwardsConfig>(10)
    }
}
