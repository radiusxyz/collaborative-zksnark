use super::silly::MySillyCircuit;
use ark_crypto_primitives::FixedLengthCRH;
use ark_ec::PairingEngine;
use ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof, ProvingKey};
use ark_std::{test_rng, UniformRand};
use mpc_algebra::*;
use mpc_algebra::Reveal;

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
