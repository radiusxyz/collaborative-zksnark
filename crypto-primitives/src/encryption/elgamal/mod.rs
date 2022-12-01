#[cfg(feature = "r1cs")]
pub mod constraints;

use crate::encryption::AsymmetricEncryptionScheme;
use crate::Error;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{fields::PrimeField, UniformRand};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::vec::Vec;

pub struct ElGamal<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

pub struct Parameters<C: ProjectiveCurve> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as ProjectiveCurve>::Affine;

pub struct SecretKey<C: ProjectiveCurve>(pub C::ScalarField);

pub struct Randomness<C: ProjectiveCurve>(pub C::ScalarField);

impl<C: ProjectiveCurve> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(<C as ProjectiveCurve>::ScalarField::rand(rng))
    }
}

pub type Plaintext<C> = <C as ProjectiveCurve>::Affine;

pub type Ciphertext<C> = (
    <C as ProjectiveCurve>::Affine,
    <C as ProjectiveCurve>::Affine,
);

impl<C: ProjectiveCurve> AsymmetricEncryptionScheme for ElGamal<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Randomness = Randomness<C>;
    type Plaintext = Plaintext<C>;
    type Ciphertext = Ciphertext<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        // get a random generator
        let generator = C::rand(rng).into();

        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // get a random element from the scalar field
        let secret_key: <C as ProjectiveCurve>::ScalarField = C::ScalarField::rand(rng);

        /* // zeroknight
        the trait bound `<<C as ProjectiveCurve>::ScalarField as PrimeField>::BigInt: From<<C as ProjectiveCurve>::ScalarField>` is not satisfied
        required for `<C as ProjectiveCurve>::ScalarField` to implement `Into<<<C as ProjectiveCurve>::ScalarField as PrimeField>::BigInt>`
         */

        // compute secret_key*generator to derive the public key
        let public_key = pp.generator.scalar_mul(secret_key).into();    // zeroknight mul -> scalar_mul

        Ok((public_key, SecretKey(secret_key)))
    }

    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: Vec<Self::Plaintext>,
        r: &Self::Randomness,
    ) -> Result<Vec<Self::Ciphertext>, Error> {
        let msg_iter = message.iter();
        // compute s = r*pk
        let s = pk.scalar_mul(r.0).into();  // zeroknight mul -> scalar_mul
        // compute c1 = r*generator
        let c1 = pp.generator.scalar_mul(r.0).into();   // zeroknight mul -> scalar_mul
        let mut cipher_vec = vec!();

        for msg in msg_iter {
            // compute c2 = m + s
            let c2 = *msg + s;
            cipher_vec.push((c1, c2));
        }

        Ok(cipher_vec)
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: Vec<Self::Ciphertext>,
    ) -> Result<Vec<Self::Plaintext>, Error> {
        let cipher_iter = ciphertext.iter();
        let mut plain_vec = vec!();

        for cipher in cipher_iter {
            let c1: <C as ProjectiveCurve>::Affine = cipher.0;
            let c2: <C as ProjectiveCurve>::Affine = cipher.1;
    
            // compute s = secret_key * c1
            let s = c1.scalar_mul(sk.0);    // zeroknight mul -> scalar_mul
            let s_inv = -s;
    
            // compute message = c2 - s
            let m = c2 + s_inv.into_affine();
            plain_vec.push(m);
        }

        Ok(plain_vec)
    }
}

#[cfg(test)]
mod test {
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_std::{test_rng, UniformRand, vec::Vec};

    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;

    use crate::encryption::elgamal::{ElGamal, Randomness};
    use crate::encryption::{AsymmetricEncryptionScheme, sub_strings};

    #[test]
    fn test_elgamal_encryption() {
        let rng = &mut test_rng();

        // setup and key generation
        let parameters = ElGamal::<JubJub>::setup(rng).unwrap();
        let (pk, sk) = ElGamal::<JubJub>::keygen(&parameters, rng).unwrap();

        // get a random msg and encryption randomness
        // let msg = JubJub::rand(rng).into();
        let plain_text = "012345678901234567890123456789012345678901";
        
        let msg_vec = sub_strings(plain_text, 32);
        let mut msg_affine_vec : Vec<<JubJub as ProjectiveCurve>::Affine> = vec!();
        let msg_iter = msg_vec.iter();

        for msg in msg_iter {
            let mut bytes = hex::decode(*msg).unwrap();
            bytes.reverse();
            let msg_affine = <JubJub as ProjectiveCurve>::Affine::from_random_bytes(&bytes).unwrap();
            let msg_var = msg_affine.mul_by_cofactor();
            msg_affine_vec.push(msg_var);
        }

        let r = Randomness::rand(rng);

        // encrypt and decrypt the message
        let cipher_vec = ElGamal::<JubJub>::encrypt(&parameters, &pk, msg_affine_vec.clone(), &r).unwrap();
        println!("{:?}", cipher_vec);
        let check_msg_vec = ElGamal::<JubJub>::decrypt(&parameters, &sk, cipher_vec).unwrap();

        assert_eq!(msg_affine_vec.len(), check_msg_vec.len());

        for i in 0..msg_affine_vec.len() {
            assert_eq!(msg_affine_vec[i], check_msg_vec[i]);
        }
        
    }
}
