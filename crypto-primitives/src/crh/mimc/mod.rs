use core::marker::PhantomData;

// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-377 pairing-friendly elliptic curve.
use ark_ff::{PrimeField};
use ark_std::{rand::Rng};

use crate::crh::FixedLengthCRH;
use crate::Error;
use crate::Vec;

pub struct MimcCRH<F: PrimeField> {
//    pub constants: &'a [F],
    window: PhantomData<F>,
}

#[derive(Clone, Default)]
pub struct MimcParameters<F: PrimeField> {
    pub constants : Vec<F>,
}

pub const MIMC_ROUNDS: usize = 322;

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
pub fn mimc<F: PrimeField>(mut xl: F, mut xr: F, constants: &[F]) -> F {
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

impl<F:PrimeField> FixedLengthCRH for MimcCRH<F> {
    const INPUT_SIZE_BITS: usize = 2usize;
    type Output = F;
    type Parameters = MimcParameters<F>;


    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        //let rng = &mut test_rng();
        let constants = (0..MIMC_ROUNDS).map(|v| F::from_random_bytes(&[v as u8]).unwrap()).collect::<crate::Vec<F>>();
        
        Ok(Self::Parameters{
            constants
        })
    }

    fn evaluate(_parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        //let rng = &mut test_rng();
        
        // Generate the MiMC round constants
        let constants : Vec<F> = (0..MIMC_ROUNDS).map(|v| F::from_random_bytes(&[v as u8]).unwrap()).collect();

        //let input_rng: [u8; 32] = rng.gen();
        let xl = F::from_random_bytes(input).unwrap();
        let xr = F::from_random_bytes(input).unwrap();
        //let xl = rng.gen();
        //let xr = rng.gen();

        let image = mimc(xl, xr, &constants);

        Ok(image)
    }
}

#[test]
fn test_minc() {
    use ark_ed_on_bls12_381::Fr;
    use ark_std::test_rng;
    
    let rng = &mut test_rng();
    let params = <MimcCRH<Fr> as FixedLengthCRH>::setup(rng).unwrap();

    let val = <MimcCRH<Fr> as FixedLengthCRH>::evaluate(&params, &[1,2,3])
                                                .unwrap();
    
    println!("MIMC:{:?}", val);
}



