
use super::round_constants::u64_from_buffer;
use super::WIDTH;
use ark_ed_on_bls12_381::{Fq, Fr};
use ark_ff::{Zero, PrimeField};

pub fn mds_matrix() -> [[Fr; WIDTH]; WIDTH] {

    let bytes = include_bytes!("./assets/mds.bin");
    let mut mds = [[Fr::zero(); WIDTH]; WIDTH];

    let mut k = 0;
    let mut i = 0;

    while i < WIDTH {
        let mut j = 0;
        while j < WIDTH {
            let a = u64_from_buffer(&bytes, k);
            let b = u64_from_buffer(&bytes, k + 8);
            let c = u64_from_buffer(&bytes, k + 16);
            let d = u64_from_buffer(&bytes, k+24);

            let list = [a.to_be_bytes(), b.to_be_bytes(), c.to_be_bytes(), d.to_be_bytes()].concat();

            k += 32;
            mds[i][j] = Fr::from_le_bytes_mod_order(list.as_slice());
            j += 1;

        }
        i += 1;
    }
    mds
}

#[test]
fn test() {
    let matrix = mds_matrix();
    let zero = Fr::zero();
    let has_zero = matrix.iter().any(|&x| 
        x.iter().any(|&y| y == zero));

    for mds in matrix.iter() {
        println!("{:?}", mds);
    }

    assert!(!has_zero);
}
