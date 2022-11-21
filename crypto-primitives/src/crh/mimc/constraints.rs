use core::marker::PhantomData;
//use core::ops::{MulAssign, AddAssign};
use crate::crh::FixedLengthCRHGadget;
//use crate::Vec; // what for?!
use ark_ff::{Field, PrimeField};

//use ark_r1cs_std::ToConstraintFieldGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::{AllocVar};
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::SynthesisError;

use core::borrow::Borrow;   //Borrow
use ark_relations::r1cs::Namespace;
use ark_r1cs_std::prelude::AllocationMode;

use super::MimcCRH;
use super::{MimcParameters};

#[derive(Derivative, Clone)]
pub struct MimcCRHParametersVar<F: Field> {
    pub constants: Vec<F>,
}

pub struct MimcCRHGadget<F: Field> {
    window: PhantomData<F>,
}

impl<F: PrimeField> FixedLengthCRHGadget<MimcCRH<F>, F> for MimcCRHGadget<F> {
    /*
    pub trait FixedLengthCRHGadget<H: FixedLengthCRH, ConstraintF: Field>: Sized {

        type OutputVar..
        type ParametersVar: AllocVar<H::Parameters, ConstraintF> + Clone;

        fn evaluate(
            parameters: &Self::ParametersVar,
            input: &[UInt8<ConstraintF>],
        ) -> Result<Self::OutputVar, SynthesisError>;
    */

    /*
        type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<H::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;
     */
    type OutputVar = FpVar<F>;

    /*
    pub trait FixedLengthCRHGadget<H: FixedLengthCRH, ConstraintF: Field>: Sized {
    type ParametersVar: AllocVar<H::Parameters, ConstraintF> + Clone;
    */
    type ParametersVar = MimcCRHParametersVar<F>;
    // ark_r1cs_std::alloc::AllocVar<MimcParameters<F>, F>

    fn evaluate(
        _parameters: &Self::ParametersVar,
        _input: &[UInt8<F>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        todo!()

        /*
        assert_eq!(parameters.constants.len(), MIMC_ROUNDS);

        let mut xl_value = input.to_constraint_field()?;
        let mut xr_value = input.to_constraint_field()?;    // the same value

        for i in 0..MIMC_ROUNDS {
            // xL, xR := xR + (xL + Ci)^3, xL

            //tmp = (xL + Ci)^2
            let tmp_value = xl_value.iter().map( |mut e| {
                e.add_assign(&parameters.constants[i]);
                e.square_in_place();
                e
            });

            // constraint (xl + Ci)(xl + Ci) = tmp

            // new_xL = xR + (xL + Ci)^3
            // new_xL = xR + tmp * (xL + Ci)
            // new_xL - xR = tmp * (xL + Ci)
            let new_xl_value = xl_value.iter().map(|mut e| {
                e.add_assign(&parameters.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&xr_value.unwrap());
                e
            })

            let new_xl = if i == (MIMC_ROUNDS - 1) {
                // the last round, xL is our image and so we allocate a public input.
            }

            // constratins : tmp * (xl + Ci) = new_xl - xr

            // xR = xL
            xr_value = xl_value;

            // xL = new_xL
            xl = new_xl;
            xl_value = new_xl_value;
        }
        Ok(())
        */
        

    }
}

/*
ark_r1cs_std::alloc
pub trait AllocVar<V, F>
where
    F: Field,
    Self: Sized,
    V: ?Sized, 
*/

impl<F:PrimeField> AllocVar<MimcParameters<F>, F> for MimcCRHParametersVar<F> {
    fn new_variable<T: Borrow<MimcParameters<F>>>(
        _cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(Self {constants: params.constants })
    }
}
