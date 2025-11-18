//! Efficient fixed-base scalar multiplication on SNARK-friendly edwards curves
//!
//! Multiplication is mostly done in equivalent affine montgomery coordinates
//! using 3-bit lookup windows
mod convert;
mod lookup;
pub mod scalar_mul;
