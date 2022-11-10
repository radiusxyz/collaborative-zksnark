use ark_crypto_primitives::{
    crh::{poseidon::{PoseidonCRH, Poseidon, PoseidonRoundParams}, bowe_hopwood::CRH},
    crh::poseidon::sbox::PoseidonSbox,
    crh::FixedLengthCRH, FixedLengthCRHGadget,
};

// constraints
use ark_crypto_primitives::{
    crh::poseidon::constraints::{PoseidonRoundParamsVar, PoseidonCRHGadget},
};

use ark_ff::{Field, PrimeField, ToConstraintField};

use ark_relations::{
    r1cs::{SynthesisError,
    ConstraintSystemRef,
    ConstraintSystem,
    ConstraintSynthesizer},   // ../snark/relations
};

// [Important!!] ark-bls12-377 and bls12-381 doesn't work!!!! by zeroknight
use ark_ed_on_bls12_381::Fq;

// 
use ark_r1cs_std::{alloc::AllocVar, prelude::*};
//use ark_ff::ToConstraintField;
//use ark_std::vec;

use ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof, ProvingKey, create_random_proof};
use ark_bls12_381::Bls12_381;


// Declare new type
pub type CRHFunction = PoseidonCRH<Fq, PParams>;
pub type CRHParam = <CRHFunction as FixedLengthCRH>::Parameters;
pub type CRHInput = [u8; 32];
pub type CRHOutput = <CRHFunction as FixedLengthCRH>::Output;

/*
#[derive(Clone)]
pub struct PoseidonCircuit<F: Field> { // Field vs Primefield with PoseidonRoundParamsVar
    pub a: Option<F>,
    pub param: CRHParam,
    pub input: CRHInput,
    pub output: CRHOutput,
}
*/
#[derive(Clone)]
pub struct PoseidonCircuit {
    pub param: CRHParam,
    pub input: CRHInput,
    pub output: CRHOutput,
}


impl ConstraintSynthesizer<Fq> for PoseidonCircuit {
    fn generate_constraints (
        self,
        cs: ConstraintSystemRef<Fq>,
    ) -> Result<(), SynthesisError> {

/*

/// Specifies how variables of type `Self` should be allocated in a
/// `ConstraintSystem`.
pub trait AllocVar<V, F: Field>
where
    Self: Sized,
    V: ?Sized,
{
    - new_variable, new_constant, new_input, new_witness

    fn new_input<T: Borrow<V>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
*/
        // parameters for Poseidon
        let pos_param_var = PoseidonRoundParamsVar::new_input(
            ark_relations::ns!(cs, "gadget_parameters"),
            || { Ok(&self.param) }
        ).unwrap();    // new_input from a trait 'AllocVar' 

        // build a circuit
        poseidon_circuit_helper(&self.input, &self.output, cs, pos_param_var)?;

        Ok(())
    }
}

pub const POSEIDON_WIDTH: usize = 6;
pub const POSEIDON_FULL_ROUNDS_BEGINNING: usize = 8;
pub const POSEIDON_FULL_ROUNDS_END: usize = 0;
pub const POSEIDON_PARTIAL_ROUNDS: usize = 36;
pub const POSEIDON_SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);

#[derive(Default, Clone, Debug)]
pub struct PParams;
impl PoseidonRoundParams<Fq> for PParams {
    const WIDTH: usize = POSEIDON_WIDTH;
    const FULL_ROUNDS_BEGINNING: usize = POSEIDON_FULL_ROUNDS_BEGINNING;
    const FULL_ROUNDS_END: usize = POSEIDON_FULL_ROUNDS_END;
    const PARTIAL_ROUNDS: usize = POSEIDON_PARTIAL_ROUNDS;
    const SBOX: PoseidonSbox = POSEIDON_SBOX;
}

pub fn poseidon_parameters_for_test1<F: PrimeField>(mut pos: Poseidon<F, PParams>) -> Poseidon<F, PParams> {
    //let alpha = 5;
    let mds = vec![
        vec![
            F::from_str(
                "43228725308391137369947362226390319299014033584574058394339561338097152657858",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "20729134655727743386784826341366384914431326428651109729494295849276339718592",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "14275792724825301816674509766636153429127896752891673527373812580216824074377",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "43228725308391137369947362226390319299014033584574058394339561338097152657858",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "20729134655727743386784826341366384914431326428651109729494295849276339718592",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "14275792724825301816674509766636153429127896752891673527373812580216824074377",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "3039440043015681380498693766234886011876841428799441709991632635031851609481",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "6678863357926068615342013496680930722082156498064457711885464611323928471101",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "37355038393562575053091209735467454314247378274125943833499651442997254948957",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "3039440043015681380498693766234886011876841428799441709991632635031851609481",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "6678863357926068615342013496680930722082156498064457711885464611323928471101",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "37355038393562575053091209735467454314247378274125943833499651442997254948957",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "26481612700543967643159862864328231943993263806649000633819754663276818191580",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "30103264397473155564098369644643015994024192377175707604277831692111219371047",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5712721806190262694719203887224391960978962995663881615739647362444059585747",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "26481612700543967643159862864328231943993263806649000633819754663276818191580",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "30103264397473155564098369644643015994024192377175707604277831692111219371047",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5712721806190262694719203887224391960978962995663881615739647362444059585747",
            )
            .map_err(|_| ())
            .unwrap(),

        ],
         vec![
            F::from_str(
                "43228725308391137369947362226390319299014033584574058394339561338097152657858",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "20729134655727743386784826341366384914431326428651109729494295849276339718592",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "14275792724825301816674509766636153429127896752891673527373812580216824074377",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "43228725308391137369947362226390319299014033584574058394339561338097152657858",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "20729134655727743386784826341366384914431326428651109729494295849276339718592",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "14275792724825301816674509766636153429127896752891673527373812580216824074377",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "3039440043015681380498693766234886011876841428799441709991632635031851609481",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "6678863357926068615342013496680930722082156498064457711885464611323928471101",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "37355038393562575053091209735467454314247378274125943833499651442997254948957",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "3039440043015681380498693766234886011876841428799441709991632635031851609481",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "6678863357926068615342013496680930722082156498064457711885464611323928471101",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "37355038393562575053091209735467454314247378274125943833499651442997254948957",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "26481612700543967643159862864328231943993263806649000633819754663276818191580",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "30103264397473155564098369644643015994024192377175707604277831692111219371047",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5712721806190262694719203887224391960978962995663881615739647362444059585747",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "26481612700543967643159862864328231943993263806649000633819754663276818191580",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "30103264397473155564098369644643015994024192377175707604277831692111219371047",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5712721806190262694719203887224391960978962995663881615739647362444059585747",
            )
            .map_err(|_| ())
            .unwrap(),

        ],
    ];
	
    let mut rng = ark_std::test_rng();
    
    //let mut seed =[0u8; 32];
    //let mut rng = ChaCha20Rng::from_seed(seed);
    
    let  rng1 = F::rand(&mut rng);
    let mut vals: Vec<F> = vec![rng1];
    let mut  k = 0;
    for i in 0..269 {
        k = k + 1;
        
        //seed[i%8] = seed[i%8]+1;
        //let mut rng = ChaCha20Rng::from_seed(seed);
        
        let mut rng = ark_std::test_rng();
        let  rng1 = F::rand(&mut rng);
        vals.push(rng1);
        if k>(32*7-1){
            k = 0;
        }
    }
    //println("vals = {:?}",vals);
    pos.mds_matrix=mds;
    pos.round_keys=vals;
    pos.params = PParams;
    pos

}

pub fn tryout_poseidon() {

    let mut rng = &mut ark_std::test_rng();
    // PoseidonCRH::<Fq, PParams> doesn't work..
    let mut parameter = CRHFunction::setup(rng).unwrap();
    parameter = poseidon_parameters_for_test1(parameter);

    let inp = [32u8; 32];
    let out = <CRHFunction as FixedLengthCRH>::evaluate(&parameter, &inp).unwrap();

    // build the circuit
    let circuit = PoseidonCircuit {
        // pub type CRHFunction = PoseidonCRH<Fq, PParams>;
        param: parameter.clone(),   // pub type CRHParam = <CRHFunction as FixedLengthCRH>::Parameters;
        input: inp, // pub type CRHInput = [u8; 32];
        output: out,    // pub type CRHOutput = <CRHFunction as FixedLengthCRH>::Output;
    };

    // setup
    let mut rng_setup = &mut ark_std::test_rng();
/*
ark_groth16::generator
pub fn generate_random_parameters<E, C, R>(circuit: C, rng: &mut R) -> R1CSResult<ProvingKey<E>>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
 */
    let params = generate_random_parameters::<Bls12_381,_,_>(circuit.clone(), rng_setup).unwrap();

/* 
ark_groth16::prover
pub fn create_random_proof<E, C, R>(circuit: C, pk: &ProvingKey<E>, rng: &mut R) -> R1CSResult<Proof<E>>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
*/
    let mut rng_prove = &mut ark_std::test_rng();
    let proof = create_random_proof(circuit.clone(), &params, rng_prove).unwrap();

    // verify
    let pvk = prepare_verifying_key(&params.vk);
    let output_fq: Vec<Fq> = ToConstraintField::<Fq>::to_field_elements(&out).unwrap();
/*
pub fn verify_proof<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::Fr],
) -> R1CSResult<bool>
 */
    let res = verify_proof(&pvk, &proof, &output_fq).unwrap();

    println!("{}", out);

}

pub fn poseidon_circuit_helper(
    input: &[u8; 32],
    output: &CRHOutput, //<CRHFunction as FixedLengthCRH>::Output;
    cs: ConstraintSystemRef<Fq>, // A shared reference to a constraint system that can be stored in high level variables.
                                    // Fq : ark_bls12_381::fields::fr  |   pub type Fr = Fp256<FrParameters>
    // struct PoseidonRoundParamsVar<F: PrimeField, P: PoseidonRoundParams<F>>
    pos_param_var: PoseidonRoundParamsVar<Fq, PParams>,
) -> Result<(), SynthesisError> {

    // Allocate parameter for Poseidon
    let parameters_var = pos_param_var;

    // Allocation inputs    .. what about witness or public input?!
    //ark_r1cs_std::bits::uint8::UInt8
        // pub fn new_witness_vec(cs: impl Into<Namespace<F>>, values: &[impl Into<Option<u8>> + Copy]) -> Result<Vec<Self>, SynthesisError>
    let intput_var = UInt8::new_witness_vec(ark_relations::ns!(cs, "declare_input"), input)?;

    // Allocate output which will be evaluated in the circuit
    let output_var = PoseidonCRHGadget::evaluate(&parameters_var, &intput_var)?;

    // Allocate actual output from outside of the circuit
    let actual_out_var = <PoseidonCRHGadget<Fq, PParams> as FixedLengthCRHGadget<_, Fq>>::OutputVar::new_input(
        ark_relations::ns!(cs, "declare_output"),
        || Ok(output),
    )?;

    // Constraint to compare the outputs
    output_var.enforce_equal(&actual_out_var)?;

    Ok(())
}

#[test]
fn test_poseidon_circuit() {
    tryout_poseidon();
}

#[test]
fn test_poseidon_evaluate() {
    let mut rng = ark_std::test_rng();
    let mut parameter = CRHFunction::setup(&mut rng).unwrap();
    parameter = poseidon_parameters_for_test1(parameter);

    let inp = [32u8; 32];
    //output
    let out = <CRHFunction as FixedLengthCRH>::evaluate(&parameter, &inp).unwrap();
    
    let cs = ConstraintSystem::new_ref();
    let param_var = PoseidonRoundParamsVar::new_witness(ark_relations::ns!(cs, "t"), ||Ok(parameter.clone())).unwrap();
    let out_var = PoseidonCRHGadget::evaluate(&param_var,
                                              &UInt8::new_witness_vec(ark_relations::ns!(cs, "declare_input"), &inp).unwrap()).unwrap();

    assert_eq!(out, out_var.value().unwrap());
}