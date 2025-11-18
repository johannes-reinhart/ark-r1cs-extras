#![allow(unused_imports)]
//! This module contains macros for logging to stdout a trace of R1CS constraints
//! for an annotated circuit. One can use this code as follows:
//! ```
//! use ark_r1cs_tools::{start_r1cs_profile, end_r1cs_profile};
//! # use ark_r1cs_std::fields::fp::FpVar;
//! # use ark_r1cs_std::eq::EqGadget;
//! # use ark_r1cs_std::alloc::AllocVar;
//! # use ark_relations::r1cs::{ConstraintSystem, SynthesisError};
//! # use ark_bn254::Fr;
//! let cs = ConstraintSystem::new_ref();
//! let start = start_r1cs_profile!(|| "Equality constraint", cs);
//! let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3)))?;
//! let b = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3)))?;
//! a.enforce_equal(&b)?;
//! end_r1cs_profile!(start);
//! # Ok::<(), SynthesisError>(())
//! ```
//! The foregoing code should log the following to stdout.
//! ```text
//! Start: Equality constraint
//! ..End: Equality constraint... 1 constr 1 wit 0 io
//! ```
//!
//! These macros can be arbitrarily nested, and the nested nature is made apparent
//! in the output. F
//!
//! Additionally, one can use the `add_to_trace` macro to log additional context
//! in the output.
pub use self::inner::*;

#[macro_use]
#[cfg(feature = "r1cs-profile")]
pub mod inner {
    use ark_ff::Field;
    use ark_relations::r1cs::ConstraintSystemRef;
    pub use colored::Colorize;
    use core::fmt::{Display, Formatter};

    // r1cs-trace requires std, so these imports are well-defined
    pub use std::{
        format,
        ops::Sub,
        println,
        string::{String, ToString},
        sync::atomic::{AtomicUsize, Ordering},
        time::Instant,
    };

    pub static NUM_INDENT: AtomicUsize = AtomicUsize::new(0);
    pub const PAD_CHAR: &str = "·";

    #[derive(Debug, Clone)]
    pub struct ProfilingInfo {
        pub num_constraints: usize,
        pub num_witness: usize,
        pub num_io: usize,
    }

    impl Sub for ProfilingInfo {
        type Output = Self;

        fn sub(self, rhs: Self) -> Self::Output {
            ProfilingInfo {
                num_constraints: self.num_constraints - rhs.num_constraints,
                num_witness: self.num_witness - rhs.num_witness,
                num_io: self.num_io - rhs.num_io,
            }
        }
    }

    impl Display for ProfilingInfo {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "{} constr {} wit {} io",
                self.num_constraints, self.num_witness, self.num_io
            )
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProfilingTag<F: Field> {
        pub msg: String,
        pub cs: ConstraintSystemRef<F>,
        pub info: ProfilingInfo,
    }

    #[macro_export]
    macro_rules! start_r1cs_profile {
        ($msg:expr, $cs:ident) => {{
            use $crate::r1cs_profile::inner::{
                compute_indent, get_profiling_info, Colorize, Ordering, ToString, NUM_INDENT,
            };

            let msg = $msg();
            let start_info = "Start:".yellow().bold();
            let indent_amount = 2 * NUM_INDENT.fetch_add(1, Ordering::Relaxed);
            let indent = compute_indent(indent_amount);
            let cs = $cs.clone();
            let info = get_profiling_info(&cs);

            $crate::r1cs_profile::println!("{}{:8} {}", indent, start_info, msg);
            $crate::r1cs_profile::ProfilingTag {
                msg: msg.to_string(),
                cs,
                info,
            }
        }};
    }

    #[macro_export]
    macro_rules! end_r1cs_profile {
        ($tag:expr) => {{
            end_r1cs_profile!($tag, || "");
        }};
        ($tag:expr, $msg:expr) => {{
            use $crate::r1cs_profile::inner::{
                compute_indent, format, get_profiling_info, Colorize, Ordering, NUM_INDENT,
            };

            let info = $tag.info;
            let final_info = get_profiling_info(&$tag.cs);
            let diff_info = final_info - info;

            let end = "End:".green().bold();
            let message = format!("{} {}", $tag.msg, $msg());

            let indent_amount = 2 * NUM_INDENT.fetch_sub(1, Ordering::Relaxed);
            let indent = compute_indent(indent_amount);

            $crate::r1cs_profile::println!(
                "{}{:8} {:.<pad$}{}",
                indent,
                end,
                message,
                diff_info,
                pad = 75 - indent_amount
            );
        }};
    }

    #[macro_export]
    macro_rules! add_to_r1cs_profile {
        ($title:expr, $msg:expr) => {{
            use $crate::r1cs_profile::{
                compute_indent, compute_indent_whitespace, format, AtomicUsize, Colorize, Instant,
                Ordering, ToString, NUM_INDENT, PAD_CHAR,
            };

            let start_msg = "StartMsg".yellow().bold();
            let end_msg = "EndMsg".green().bold();
            let title = $title();
            let start_msg = format!("{}: {}", start_msg, title);
            let end_msg = format!("{}: {}", end_msg, title);

            let start_indent_amount = 2 * NUM_INDENT.fetch_add(0, Ordering::Relaxed);
            let start_indent = compute_indent(start_indent_amount);

            let msg_indent_amount = start_indent_amount + 2;
            let msg_indent = compute_indent_whitespace(msg_indent_amount);
            let mut final_message = "\n".to_string();
            for line in $msg().lines() {
                final_message += &format!("{}{}\n", msg_indent, line,);
            }

            $crate::r1cs_profile::println!("{}{}", start_indent, start_msg);
            $crate::r1cs_profile::println!("{}{}", msg_indent, final_message,);
            $crate::r1cs_profile::println!("{}{}", start_indent, end_msg);
        }};
    }

    pub fn get_profiling_info<F: Field>(cs: &ConstraintSystemRef<F>) -> ProfilingInfo {
        let num_constraints = cs.num_constraints();
        let num_io = cs.num_instance_variables();
        let num_witness = cs.num_witness_variables();
        ProfilingInfo {
            num_constraints,
            num_witness,
            num_io,
        }
    }

    pub fn compute_indent_whitespace(indent_amount: usize) -> String {
        let mut indent = String::new();
        for _ in 0..indent_amount {
            indent.push_str(" ");
        }
        indent
    }

    pub fn compute_indent(indent_amount: usize) -> String {
        let mut indent = String::new();
        for _ in 0..indent_amount {
            indent.push_str(&PAD_CHAR.white());
        }
        indent
    }
}

#[macro_use]
#[cfg(not(feature = "r1cs-profile"))]
mod inner {
    pub struct ProfilingInfo;

    #[macro_export]
    macro_rules! start_r1cs_profile {
        ($msg:expr, $cs:ident) => {{
            let _ = $msg;
            let _ = $cs;
            $crate::r1cs_profile::ProfilingInfo
        }};
    }
    #[macro_export]
    macro_rules! add_to_r1cs_profile {
        ($title:expr, $msg:expr) => {
            let _ = $msg;
            let _ = $title;
        };
    }

    #[macro_export]
    macro_rules! end_r1cs_profile {
        ($tag:expr, $msg:expr) => {
            let _ = $msg;
            let _ = $tag;
        };
        ($tag:expr) => {
            let _ = $tag;
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::{ConstraintSystem, SynthesisError};

    #[test]
    fn print_start_end() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let start = start_r1cs_profile!(|| "Hello", cs);
        end_r1cs_profile!(start);
    }

    #[test]
    fn print_add() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let start = start_r1cs_profile!(|| "Hello", cs);
        add_to_r1cs_profile!(|| "HelloMsg", || "Hello, I\nAm\nA\nMessage");
        end_r1cs_profile!(start);
    }

    #[test]
    fn equality_constraint() -> Result<(), SynthesisError> {
        use ark_r1cs_std::alloc::AllocVar;
        use ark_r1cs_std::eq::EqGadget;
        use ark_r1cs_std::fields::fp::FpVar;

        let cs = ConstraintSystem::new_ref();
        let start = start_r1cs_profile!(|| "Equality constraint", cs);
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3)))?;
        let b = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3)))?;
        a.enforce_equal(&b)?;
        end_r1cs_profile!(start);
        Ok(())
    }
}
