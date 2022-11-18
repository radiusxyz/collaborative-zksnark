use core::marker::PhantomData;

// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-377 pairing-friendly elliptic curve.
use ark_ff::Field;
use ark_std::{rand::Rng, test_rng};


use crate::crh::FixedLengthCRH;
use crate::Error;
use crate::Vec;

pub struct CRH<'a, F: Field> {
    constants: &'a [F],
    window: PhantomData<F>,
}

#[derive(Clone, Default)]
pub struct Parameters;

const MIMC_ROUNDS: usize = 322;

#[cfg(feature = "r1cs")]
pub mod constraints;

/// This is an implementation of MiMC, specifically a
/// variant named `LongsightF322p3` for BLS12-377.
/// See http://eprint.iacr.org/2016/492 for more
/// information about this construction.
///
/// ```
/// function LongsightF322p3(xL ⦂ Fp, xR ⦂ Fp) {
///     for i from 0 up to 321 {
///         xL, xR := xR + (xL + Ci)^3, xL
///     }
///     return xL
/// }
/// ```
pub fn mimc<F: Field>(mut xl: F, mut xr: F, constants: &[F]) -> F {
    assert_eq!(constants.len(), MIMC_ROUNDS);

    for i in 0..MIMC_ROUNDS {
        let mut tmp1 = xl;
        tmp1.add_assign(&constants[i]);
        let mut tmp2 = tmp1;
        tmp2.square_in_place();
        tmp2.mul_assign(&tmp1);
        tmp2.add_assign(&xr);
        xr = xl;
        xl = tmp2;
    }

    xl
}

impl<'a, F:Field> FixedLengthCRH for CRH<'a, F> {
    const INPUT_SIZE_BITS: usize = 2usize;
    type Output = F;
    type Parameters = Parameters;


    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let rng = &mut ark_std::test_rng();
        
        //let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<crate::Vec<F>>();
        
        Ok(Self::Parameters{})
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let rng = &mut test_rng();
        
        // Generate the MiMC round constants
        let constants : Vec<F> = (0..MIMC_ROUNDS).map(|v| F::from_random_bytes(&[v as u8]).unwrap()).collect();

        let xl = rng.gen();
        let xr = rng.gen();

        let image = mimc(xl, xr, &constants);

        Ok(image)
    }
}



