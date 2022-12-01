use ark_crypto_primitives::encryption::{constraints::AsymmetricEncryptionGadget};
use ark_std::{vec::Vec};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};

use ark_crypto_primitives::encryption::elgamal::{constraints::ElGamalEncGadget, ElGamal, Parameters, Plaintext, Ciphertext, Randomness, PublicKey};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{SynthesisError, ConstraintSystemRef, ConstraintSynthesizer};


#[derive(Clone)]
pub struct ElGamalCircuit {
    pub parameters: Parameters<JubJub>,
    pub input: Vec<Plaintext<JubJub>>,
    pub output: Vec<Ciphertext<JubJub>>,
    pub randomness: Randomness<JubJub>,
    pub public_key: PublicKey<JubJub>
}

impl ConstraintSynthesizer<Fq> for ElGamalCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {

        elgamal_circuit_helper(cs, self.parameters, self.input, self.output, self.randomness, self.public_key)?;

        Ok(())
    }
}

fn elgamal_circuit_helper(
    cs: ConstraintSystemRef<Fq>,
    parameters: Parameters<JubJub>,
    input:  Vec<Plaintext<JubJub>>,
    output:  Vec<Ciphertext<JubJub>>,
    randomness: Randomness<JubJub>,
    public_key: PublicKey<JubJub>,
    ) -> Result<(), SynthesisError> 
{

    type PlainEnc = ElGamal<JubJub>;
    type EncGadget = ElGamalEncGadget<JubJub, EdwardsVar>;

    // construct constraint system
    let randomness_var =
        <EncGadget as AsymmetricEncryptionGadget<PlainEnc, Fq>>::RandomnessVar::new_witness(
            ark_relations::ns!(cs, "gadget_randomness"),
            || Ok(&randomness),
        )
        .unwrap();
    let parameters_var =
        <EncGadget as AsymmetricEncryptionGadget<PlainEnc, Fq>>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "gadget_parameters"),
            &parameters,
        )
        .unwrap();
    let mut msg_var_vec : Vec<<EncGadget as AsymmetricEncryptionGadget<PlainEnc, Fq>>::PlaintextVar> = vec!();
    let input_iter = input.iter();
    for plain_affine in input_iter {
        let msg_var =
        <EncGadget as AsymmetricEncryptionGadget<PlainEnc, Fq>>::PlaintextVar::new_witness(
            ark_relations::ns!(cs, "gadget_message"),
            || Ok(plain_affine),
        )
        .unwrap();
        msg_var_vec.push(msg_var);
    }
    let pk_var =
        <EncGadget as AsymmetricEncryptionGadget<PlainEnc, Fq>>::PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "gadget_public_key"),
            || Ok(&public_key),
        )
        .unwrap();

    // use gadget
    let result_var_vec =
        EncGadget::encrypt(&parameters_var, msg_var_vec, &randomness_var, &pk_var).unwrap();

    // check that result equals expected ciphertext in the constraint system
    let mut expected_var_vec = vec!();
    let primitive_output_iter = output.iter();

    for primitive_result in primitive_output_iter {
        let expected_var = <EncGadget as AsymmetricEncryptionGadget<PlainEnc, Fq>>::OutputVar::new_input(
            ark_relations::ns!(cs, "gadget_expected"),
            || Ok(primitive_result),
        )
        .unwrap();
        expected_var_vec.push(expected_var);
    }

    for i in 0..expected_var_vec.len() {
        expected_var_vec[i].enforce_equal(&result_var_vec[i]).unwrap(); 
    }


    Ok(())
}