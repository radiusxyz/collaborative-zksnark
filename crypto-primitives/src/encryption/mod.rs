#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub mod elgamal;

use crate::Error;
use ark_std::rand::Rng;
use ark_std::vec::Vec;

pub trait AsymmetricEncryptionScheme {
    type Parameters;
    type PublicKey;
    type SecretKey;
    type Randomness;
    type Plaintext;
    type Ciphertext;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: Vec<Self::Plaintext>,
        r: &Self::Randomness,
    ) -> Result<Vec<Self::Ciphertext>, Error>;

    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: Vec<Self::Ciphertext>,
    ) -> Result<Vec<Self::Plaintext>, Error>;
}

pub fn sub_strings(string: &str, sub_len: usize) -> Vec<&str> {
    let mut subs = Vec::with_capacity(string.len() / sub_len);
    let mut iter = string.chars();
    let mut pos = 0;

    while pos < string.len() {
        let mut len = 0;
        for ch in iter.by_ref().take(sub_len) {
            len += ch.len_utf8();
        }
        subs.push(&string[pos..pos + len]);
        pos += len;
    }
    subs
}
