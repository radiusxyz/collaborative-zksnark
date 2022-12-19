use std::str::FromStr;

use super::silly::MySillyCircuit;
use ark_crypto_primitives::FixedLengthCRH;
use ark_ec::PairingEngine;
use ark_ff::{PrimeField, Fp256Parameters, BigInteger256, BigInteger};
use ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof, ProvingKey, create_random_proof};
use ark_r1cs_std::fields::fp::FpVar;
use ark_sponge::poseidon::PoseidonSponge;
use ark_std::{test_rng, UniformRand};
use mpc_algebra::*;
use mpc_algebra::Reveal;

pub mod prover;
pub mod r1cs_to_qap;

// zeroknight
//use super::poseidon::PoseidonCircuit;
use super::poseidon::*;
//use super::silly::{PoseidonMpcCircuit};

/* == temporary commented out..

pub fn mpc_test_prove_and_verify_on_poseidon<E: PairingEngine, S: PairingShare<E>>(n_iters: usize) {
    let rng = &mut test_rng();

/*
/// Generates a random common reference string for
/// a circuit.
#[inline]
pub fn generate_random_parameters<E, C, R>(circuit: C, rng: &mut R) -> R1CSResult<ProvingKey<E>>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
*/
    let mut parameter = CRHFunction::setup(rng).unwrap();
    parameter = poseidon_parameters_for_test1(parameter);

    //build the circuit
    let circuit = PoseidonCircuit {
        param: parameter.clone(),
        input: None,
        output: None,
    };

    //let params = generate_random_parameters::<E,_,_>(PoseidonCircuit{a: None}, rng).unwrap();   // generate a random common reference string for a circuit
    let params = generate_random_parameters::<E,_,_>(circuit, rng).unwrap();
/*
/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: PairingEngine>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E>
 */

    let pvk = prepare_verifying_key::<E>(&params.vk);

/*
impl<E: PairingEngine, S: PairingShare<E>> Reveal
    for ProvingKey<MpcPairingEngine<E, S>>
{
    type Base = ProvingKey<E>;
    struct_reveal_simp_impl!(ProvingKey;
    vk,
    beta_g1,
    delta_g1,
    a_query,
    b_g1_query,
    b_g2_query,
    h_query,
    l_query);
}
 */

    let mpc_params = ProvingKey::from_public(params);   // macro

    for _ in 0..n_iters {
/*
pub enum MpcField<F: Field, S: FieldShare<F>> {
    Public(F),
    Shared(S),
}
 */
/*
    /// This is the scalar field of the G1/G2 groups.   // from E(PairingEngine)
    type Fr: PrimeField + SquareRootField;

    type FrShare: FieldShare<E::Fr>;    // From PairingShare
    type FqShare: FieldShare<E::Fq>;
 */
        let a = MpcField::<E::Fr, S::FrShare>::rand(rng);

/*
/// Create a Groth16 proof that is zero-knowledge.
/// This method samples randomness for zero knowledges via `rng`.
#[inline]
pub fn create_random_proof<E, C, R>(
    circuit: C,
    pk: &ProvingKey<E>,
    rng: &mut R,
) -> R1CSResult<Proof<E>>
where
    E: PairingEngine,
    //E::Fr: BatchProd,
    C: ConstraintSynthesizer<<E as PairingEngine>::Fr>,
    R: Rng,

pub struct MpcPairingEngine<E: PairingEngine, PS: PairingShare<E>> {
    _phants: PhantomData<(E, PS)>,
}
 */
        let mpc_proof = prover::create_random_proof::<MpcPairingEngine<E,S>,_,_> (
            circuit,// PoseidonCircuit { a: Some(a) },
            &mpc_params,
            rng,
        ).unwrap();

        let proof = mpc_proof.reveal(); // to construct plain data
        let pub_a = a.reveal();

/*
/// Verify a Groth16 proof `proof` against the prepared verification key `pvk`,
/// with respect to the instance `public_inputs`.
pub fn verify_proof<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::Fr],
) 
*/
        assert!(verify_proof(&pvk, &proof, &[]).unwrap());
    }
}

*/

use ark_bls12_381::Fr;
use ark_sponge::{CryptographicSponge, FieldBasedCryptographicSponge, Absorb};        // new from PoseidonSponge
use ark_sponge::constraints::CryptographicSpongeVar;
pub fn mpc_test_prove_and_verify_on_poseidon<E: PairingEngine, S: PairingShare<E>>( n_iters: usize) {

//    let input = [1u8; SIZEOFINPUT].to_vec();
    const INPTEXT:&str = "Input...";
    const LEN: usize = INPTEXT.len();
    let input = [
        INPTEXT.as_ref(),
        [0u8; SIZEOFINPUT - LEN].as_ref(),
    ]
    .concat();
    let inp = input;

    let parameter = poseidon_parameters_for_test_s::<Fr>();

    let mut native_sponge = PoseidonSponge::< >::new(&parameter);
    native_sponge.absorb(&inp);
    let out = native_sponge.squeeze_native_field_elements(SIZEOFOUTPUT);
    println!("out = {:?}", out);

    // build the circuit
    let circuit = SPNGCircuit {
        param: parameter.clone(),
        input: inp,
        output: out.clone(),
    };
    let rng = &mut test_rng();
    let zk_param = generate_random_parameters::<ark_bls12_381::Bls12_381,_,_>(circuit.clone(), rng).unwrap();

    // proving
    let rng2 = &mut test_rng();
    let proof = create_random_proof(circuit.clone(), &zk_param, rng2).unwrap();

    // verifying
    let pvk = prepare_verifying_key(&zk_param.vk);
    let res = verify_proof(&pvk, &proof, &out).unwrap();

    assert!(res);

}

pub fn mpc_test_prove_and_verify<E: PairingEngine, S: PairingShare<E>>(n_iters: usize) {
    let rng = &mut test_rng();

    let params =
        generate_random_parameters::<E, _, _>(MySillyCircuit { a: None, b: None }, rng).unwrap();
    
    let pvk = prepare_verifying_key::<E>(&params.vk);
    let mpc_params = ProvingKey::from_public(params);

    for _ in 0..n_iters {
        let a = MpcField::<E::Fr, S::FrShare>::rand(rng);
        let b = MpcField::<E::Fr, S::FrShare>::rand(rng);
        let mut c = a;
        c *= &b;

        let mpc_proof = prover::create_random_proof::<MpcPairingEngine<E, S>, _, _>(
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mpc_params,
            rng,
        )
        .unwrap();
        let proof = mpc_proof.reveal();
        let pub_a = a.reveal();
        let pub_c = c.reveal();

        assert!(verify_proof(&pvk, &proof, &[pub_c]).unwrap());
        assert!(!verify_proof(&pvk, &proof, &[pub_a]).unwrap());
    }
}

//====================================================================//

pub fn mpc_test_prove_and_verify_on_poseidon_mpc<E: PairingEngine, S:PairingShare<E>>(n_iters: usize) {

/*
    const INPTEXT: &str = "Hello, Radius";
    
    let input = INPTEXT.as_bytes().to_vec();
    
    let mut field_vec_input = Vec::<ark_bls12_381::Fr>::new();  // Temp with 
    field_vec_input = input.iter().map(|v| ark_bls12_381::Fr::from(*v)).collect();
    let mut mpc_field_input = Vec::<E::Fr>::new();
    mpc_field_input = input.iter().map(|v| E::Fr::from(*v)).collect();
    
    // elements in this parameter are 'MpcField' // MpcField::<E::Fr, S::FrShare>
    let parameter = poseidon_parameters_for_encryption::<E::Fr>();
    
    let mut native_sponge = PoseidonSponge::<E::Fr>::new(&parameter);
    native_sponge.absorb(&field_vec_input); // code : sponge-src-absorb.rs-186 for Fp256
    let out = native_sponge.squeeze_native_field_elements(SIZEOFOUTPUT);
    println!("out = {:?}", out);

    // building a circuit
    let absorb_var : Vec<_> = mpc_field_input.iter()
                                .map(|v| {
                                    FpVar::new_witness(ark_relations::ns!(cs,"absorb"),
                                    || Ok(*v)).unwrap()
                                }).collect();
*/
/*
    // circuit is not implemented based on Field which needs for MpcField
    // build the circuit
    let circuit = SPNGMpcCircuit::<MpcField::<E::Fr, S::FrShare>> { //SPNGMpcCircuit or PoseidonMpcCircuit
        param: None,
        input: None,
        output: None,
    };
    let rng = &mut test_rng();
    let zk_param = generate_random_parameters::<E,_,_>(circuit, rng).unwrap();

    let pvk = prepare_verifying_key::<E>(&zk_param.vk);
    let mpc_params = ProvingKey::from_public(zk_param);

    let mpc_proof = prover::create_random_proof::<MpcPairingEngine<E, S>,_,_>
                                            (circuit, &mpc_params, rng).unwrap();

    let proof = mpc_proof.reveal();
    
    assert!(verify_proof(&pvk, &proof, &[]).unwrap());
*/    

}

pub fn mpc_test_prove_and_verify_test<E: PairingEngine, S: PairingShare<E>>(n_iters: usize) {

    let rng = &mut test_rng();

    let mut input = Vec::new();
    input.push(MpcField::<E::Fr, S::FrShare>::rand(rng));

    //let mut output = Vec::new();
    //output.push(MpcField::<E::Fr, S::FrShare>::rand(rng));
    let mut output = Vec::new();
    //output.push(MpcField::<E::Fr, S::FrShare>::rand(rng));

    let parameter = poseidon_parameters_for_encryption::<MpcField::<E::Fr, S::FrShare>>();

    // parameters,input,output for Setup
    let parameter_e = poseidon_parameters_for_encryption::<E::Fr>();
    let mut setup_input = Vec::new();
    setup_input.push(E::Fr::rand(rng));
    let mut setup_output = Vec::new();
    setup_output.push(E::Fr::rand(rng));


    // calculate hash of the input
    let mut native_sponge = PoseidonSponge::<E::Fr>::new(&parameter_e);
    let mut input_val : E::Fr = input[0].unwrap_as_public();
    let repr = input_val.into_repr().to_bytes_be();
    let mut repr2 = ark_bls12_377::Fr::from_be_bytes_mod_order(repr.as_slice());
    native_sponge.absorb(&repr2);
    let native_out = native_sponge.squeeze_native_field_elements(SIZEOFOUTPUT);
    output.push(MpcField::<E::Fr, S::FrShare>::rand(rng));

    output = native_out.iter().map(|v| {
        //MpcField::<E::Fr, S::FrShare>::Public(*v)
        MpcField::<E::Fr, S::FrShare>::Shared(S::FrShare::from_public(*v))  // if it's Public, an error occurs.
    }).collect();

//    MpcField::<E::Fr, S::FrShare>::Public(native_out);

    let params = 
        generate_random_parameters::<E, _,_>(
            PoseidonMpcCircuit{
                param: Some(parameter_e), 
                input: Some(setup_input), 
                output: Some(setup_output)}, rng).unwrap();

    let pvk = prepare_verifying_key::<E>(&params.vk);
    let mpc_params = ProvingKey::from_public(params);

    let mpc_proof = prover::create_random_proof::<MpcPairingEngine<E,S>,_,_>(
        PoseidonMpcCircuit{
            param: Some(parameter),
            input: Some(input),
            output: Some(output.clone()),
        },
        &mpc_params,
        rng,  
    ).unwrap();

    let proof = mpc_proof.reveal();
    let pub_out = output.reveal();

    println!("proof : {:?}", proof);
    println!("public output : {:?}", pub_out);
    //assert!(verify_proof(&pvk, &proof, pub_out.as_slice()).unwrap());
    
}

#[test]
fn test_poseidon_with_primefield() {

    type testFr = ark_ed_on_bls12_381::Fr;

    const INPTEXT:&str = "Input...";
    const LEN: usize = INPTEXT.len();

    let input = [                           // length : 64 SIZEOFINPUT
        INPTEXT.as_ref(),
        [0u8; SIZEOFINPUT - LEN].as_ref(),  
    ].concat();
    let mut input_vec = Vec::<testFr>::new(); 
    let inp : Vec<u8> = input.to_vec();
    
    input_vec = inp.iter().map( |v| testFr::from_be_bytes_mod_order(&[*v])).collect();

    println!("u8 : {:?}", input);
    println!("PrimeField : {:?}", input_vec);

    let parameter = poseidon_parameters_for_encryption::<testFr>();

    let mut native_sponge = PoseidonSponge::<testFr>::new(&parameter);
    native_sponge.absorb(&input_vec);

    let out = native_sponge.squeeze_native_field_elements(SIZEOFOUTPUT);

    println!("Output : {:?}", out);

}

use mpc_algebra::MpcField;

#[test]
fn test_integrity_check_on_mpcfield() {
    type E = ark_bls12_381::Bls12_381;
    type S = mpc_algebra::AdditivePairingShare<ark_bls12_381::Bls12_381>;
    // ark_bls12_377::Bls12_377, mpc_algebra::AdditivePairingShare<ark_bls12_377::Bls12_377>,
    let mpc = MpcField::<<E as PairingEngine>::Fr, <S as PairingShare<E>>::FrShare>::from(2u8);
    let mpc_unwrap = mpc.unwrap_as_public();
    let mpc_into = mpc.into_repr();
    let mpc_from = ark_bls12_381::Fr::from_repr(mpc_into.clone());
    println!("mpc_unwrap: {:?}", mpc_unwrap);
    println!("mpc_into: {:?}", mpc_into);
    println!("mpc_from: {:?}", mpc_from);

    //
    let value = ark_bls12_381::Fr::from(2u8);
    println!("value_unwrap: {:?}", value);

    //
    let value2 = ark_bls12_381::Fr::from_le_bytes_mod_order(&[2u8]);
    println!("value2_unwrap: {:?}", value2);

}