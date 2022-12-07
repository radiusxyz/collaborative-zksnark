
use ark_ed_on_bls12_381::{Fq, EdwardsAffine, Fr};
use ark_ff::{Zero, PrimeField};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use super::WIDTH;

const CONSTANTS: usize = 960;

pub(crate) const fn u64_from_buffer<const N: usize>(buf: &[u8; N], i: usize) -> u64 {
    u64::from_le_bytes([
        buf[i],
        buf[i + 1],
        buf[i + 2],
        buf[i + 3],
        buf[i + 4],
        buf[i + 5],
        buf[i + 6],
        buf[i + 7],
    ])
}

// 'Round_constants' consists on a static reference
// that points to the pre-loaded 960 Fq constants

pub fn round_constants() -> [Fr; CONSTANTS] {
    let bytes = include_bytes!("./assets/ark.bin");
    let mut cnst = [Fr::zero(); CONSTANTS];

    let mut i = 0;
    let mut j = 0;
    while i < bytes.len() {
        let a = u64_from_buffer(&bytes, i);
        let b = u64_from_buffer(&bytes, i + 8);
        let c = u64_from_buffer(&bytes, i + 16);
        let d = u64_from_buffer(&bytes, i + 24);

        let list = [a.to_be_bytes(), b.to_be_bytes(), c.to_be_bytes(), d.to_be_bytes()].concat();//.as_slice();
        //let list_bytes = list.clone().as_slice();

        cnst[j] = Fr::from_le_bytes_mod_order(list.as_slice());
        j += 1;
        i += 32;
    }

    cnst
}

pub fn round_constants_4() -> [[Fq; WIDTH]; 67] {
    let bytes = include_bytes!("./assets/ark.bin");
    let mut cnst = [[Fq::zero(); WIDTH]; 67];

    let mut k = 0;
    let mut i = 0;

    while i < 67 {
        let mut j = 0;
        while j < WIDTH {
            let a = u64_from_buffer(&bytes, k);
            let b = u64_from_buffer(&bytes, k + 8);
            let c = u64_from_buffer(&bytes, k + 16);
            let d = u64_from_buffer(&bytes, k+24);

            let list = [a.to_be_bytes(), b.to_be_bytes(), c.to_be_bytes(), d.to_be_bytes()].concat();

            k += 32;
            cnst[i][j] = Fq::from_le_bytes_mod_order(list.as_slice());
            j += 1;

        }
        i += 1;
    }

    cnst
}



#[test]
fn test() {
    let cnst = round_constants();
    // println!("{:?}", cnst);
    
    // Check each element is non-zero
    let zero = Fr::zero();
    let has_zero = cnst.iter().any(|&x| x == zero);

// let mut buf = Vec::new();
// self.bls_scalar.serialize(&mut buf).unwrap();

    for ctant in cnst.iter() {
        let mut buf = Vec::new();
        ctant.serialize(&mut buf).unwrap();
        
        let again = Fr::deserialize(buf.as_slice()).unwrap();

        println!("{:?}", ctant);
        println!("{:?}", buf.as_slice());
    }

    assert!(!has_zero);
}