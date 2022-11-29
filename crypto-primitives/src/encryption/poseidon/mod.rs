use core::marker::PhantomData;

//use ark_bls12_377::Fr;
use ark_ff::fields::PrimeField;
//use ark_ec::ProjectiveCurve;
use ark_ec::twisted_edwards_extended::GroupProjective;
use ark_ec::models::{TEModelParameters as Parameters};

const MESSAGE_CAPACITY: usize = 2;
const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;
const HASH_WIDTH: usize = 5;

pub struct PoseidonEncryption<F> {
    pub _param: PhantomData<F>,
}

impl<F: PrimeField> PoseidonEncryption<F> {
    pub const fn new() -> Self {
        Self{ _param: PhantomData,  
        }
    }

    pub const fn capacity() -> usize {
        MESSAGE_CAPACITY
    }

    pub const fn cipher_size() -> usize {
        CIPHER_SIZE
    }

    pub fn initial_state( secret: GroupProjective<Parameters>, nonce: F) -> [F; HASH_WIDTH] 
    {
        [
            // Domain - Maximum plaintext length of the elements of Fq, as defined in the paper
            // origin : BlsScalar::from_raw([0x100000000u64, 0, 0, 0])
            F::from_be_bytes_mod_order(&[0x10u8,0,0,0]),
            
            // The size of the message is constant because any absent input is replaced by zero
            F::from_be_bytes_mod_order(&[MESSAGE_CAPACITY as u8, 0,0,0]),
            secret.x,
            secret.y,
            nonce,
        ]
    }

}