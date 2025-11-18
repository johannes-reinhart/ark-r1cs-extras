use ark_ec::twisted_edwards::{Affine, MontgomeryAffine, TECurveConfig};
use ark_ff::{Field, One, Zero};

#[derive(Debug)]
pub struct PointConversionError {}

pub fn edwards_to_montgomery<P>(
    edwards: Affine<P>,
) -> Result<MontgomeryAffine<P::MontCurveConfig>, PointConversionError>
where
    P: TECurveConfig,
{
    // The only points on the curve with x=0 or y=1 (for which birational equivalence is not valid),
    // are (0,1) and (0,-1), both of which are of low order, and should therefore not occur.
    if edwards.x.is_zero() || edwards.y.is_one() {
        return Err(PointConversionError {});
    }

    // (x, y) -> (u, v) where
    //      u = (1 + y) / (1 - y)
    //      v = u / x
    let u =
        (P::BaseField::one() + &edwards.y) * &(P::BaseField::one() - &edwards.y).inverse().unwrap();
    let v = u * &edwards.x.inverse().unwrap();
    Ok(MontgomeryAffine::new(u, v))
}
