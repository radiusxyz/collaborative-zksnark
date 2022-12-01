use super::silly::MySillyCircuit;
use ark_crypto_primitives::FixedLengthCRH;
use ark_crypto_primitives::encryption::elgamal::ElGamal;
use ark_crypto_primitives::encryption::{sub_strings, AsymmetricEncryptionScheme};
use ark_ec::{PairingEngine, ProjectiveCurve, AffineCurve};
use ark_ff::Fp256;
use ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof, ProvingKey, create_random_proof};
use ark_sponge::poseidon::PoseidonSponge;
use ark_std::{test_rng, UniformRand};
use mpc_algebra::*;
use mpc_algebra::Reveal;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};

pub mod prover;
pub mod r1cs_to_qap;

// zeroknight
//use super::poseidon::PoseidonCircuit;
use super::poseidon::*;


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

use mpc_snarks::elgamal::*;
use ark_crypto_primitives::encryption::elgamal::Randomness;
pub fn mpc_test_prove_and_verify_on_elgamal( n_iters: usize) {
    
    let rng = &mut test_rng();

    type PlainEnc = ElGamal<JubJub>;

    // compute primitive result
    let parameters = PlainEnc::setup(rng).unwrap();
    let (pk, _) = PlainEnc::keygen(&parameters, rng).unwrap();

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

    let randomness = Randomness::rand(rng);
    let primitive_result_vec = PlainEnc::encrypt(&parameters, &pk, msg_affine_vec.clone(), &randomness).unwrap();
    println!("plain output: {:#?}", primitive_result_vec);


    // build the circuit
    let circuit = ElGamalCircuit {
        parameters,
        input: msg_affine_vec,
        output: primitive_result_vec.clone(),
        randomness,
        public_key: pk,
    };

    let rng = &mut test_rng();
    let zk_param = generate_random_parameters::<ark_bls12_381::Bls12_381,_,_>(circuit.clone(), rng).unwrap();

    // proving
    let rng2 = &mut test_rng();
    let proof = create_random_proof(circuit.clone(), &zk_param, rng2).unwrap();

    println!("proof: {:#?}", proof);

    // verifying
    let pvk = prepare_verifying_key(&zk_param.vk);
    // let res = verify_proof(&pvk, &proof, &primitive_result_vec).unwrap();

    // assert!(res);
    
    }

use ark_bls12_381::Fr;
use ark_sponge::{CryptographicSponge, FieldBasedCryptographicSponge};        // new from PoseidonSponge
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
