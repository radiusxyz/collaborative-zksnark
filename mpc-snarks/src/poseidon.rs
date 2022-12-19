use std::str::FromStr;

use ark_crypto_primitives::{
    crh::{poseidon::{PoseidonCRH, Poseidon, PoseidonRoundParams}, bowe_hopwood::CRH},
    crh::poseidon::sbox::PoseidonSbox,
    crh::FixedLengthCRH, FixedLengthCRHGadget,
};

// constraints
use ark_crypto_primitives::{
    crh::poseidon::constraints::{PoseidonRoundParamsVar, PoseidonCRHGadget},
};

use ark_ff::{Field, PrimeField, ToConstraintField, UniformRand, BigInteger};

use ark_relations::{
    r1cs::{SynthesisError,
    ConstraintSystemRef,
    ConstraintSystem,
    ConstraintSynthesizer},   // ../snark/relations
};

// [Important!!] ark-bls12-377 and bls12-381 doesn't work!!!! by zeroknight
use ark_ed_on_bls12_381::Fq;

// 
use ark_r1cs_std::{alloc::AllocVar, prelude::*, fields::fp::FpVar};
//use ark_ff::ToConstraintField;
//use ark_std::vec;

use ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof, ProvingKey, create_random_proof};
use ark_bls12_381::Bls12_381;


use mpc_algebra::Reveal;
// Rand instead of ark_std::rand..
use rand_chacha::ChaCha20Rng;
use ark_std::{rand::SeedableRng, test_rng};   // from_seed

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
	
    //let mut rng = ark_std::test_rng();
    let mut seed =[0u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    
    let  rng1 = F::rand(&mut rng);
    let mut vals: Vec<F> = vec![rng1];
    let mut  k = 0;
    for i in 0..269 {
        k = k + 1;
        
        //let mut rng = ark_std::test_rng();
        seed[i%8] = seed[i%8]+1;
        let mut rng = ChaCha20Rng::from_seed(seed);
        
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

// added by zeroknight : test Poseidon..

use ark_sponge::{poseidon::{PoseidonParameters, PoseidonSponge}, FieldBasedCryptographicSponge};
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_sponge::CryptographicSponge;        // new from PoseidonSponge
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_bls12_381::Fr;

pub const SIZEOFINPUT: usize = 64;
pub const SIZEOFOUTPUT: usize = 2;
#[test]
fn test_sponge() {
    let mut rng = ark_std::test_rng();
    let cs = ConstraintSystem::new_ref();

    let absorb1: Vec<_> = (0..SIZEOFINPUT).map(|_| Fr::rand(&mut rng)).collect();

    let sponge_params = poseidon_parameters_for_test_s::<Fr>();

    // native
    let mut native_sponge = PoseidonSponge::<Fr>::new(&sponge_params);  //CryptoSage
    native_sponge.absorb(&absorb1);
    let squeeze1 = native_sponge.squeeze_field_elements::<Fr>(SIZEOFOUTPUT);

    // constraints
    let absorb1_var: Vec<_> = absorb1
                                .iter()
                                .map(|v| FpVar::new_input(ark_relations::ns!(cs, "absorb1"), 
                                ||Ok(*v)).unwrap())
                                .collect();
    let mut constraint_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &sponge_params);
    constraint_sponge.absorb(&absorb1_var);
    let squeeze2 = constraint_sponge.squeeze_field_elements(SIZEOFOUTPUT).unwrap();
    let res = squeeze2.value().unwrap();
    
    //println!("{:?}", squeeze1);
    //println!("{:?}", res);
    assert_eq!(res, squeeze1);
    assert!(cs.is_satisfied().unwrap());
}

pub fn poseidon_parameters_for_test_s<F: PrimeField>() -> PoseidonParameters<F> {
    let alpha = 17;
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
        ],
    ];
    let ark = vec![
        vec![
            F::from_str(
                "44595993092652566245296379427906271087754779418564084732265552598173323099784",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "23298463296221002559050231199021122673158929708101049474262017406235785365706",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "34212491019164671611180318500074499609633402631511849759183986060951187784466",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "19098051134080182375553680073525644187968170656591203562523489333616681350367",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "7027675418691353855077049716619550622043312043660992344940177187528247727783",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "47642753235356257928619065424282314733361764347085604019867862722762702755609",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "24281836129477728386327945482863886685457469794572168729834072693507088619997",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "12624893078331920791384400430193929292743809612452779381349824703573823883410",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "22654862987689323504199204643771547606936339944127455903448909090318619188561",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "27229172992560143399715985732065737093562061782414043625359531774550940662372",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "13224952063922250960936823741448973692264041750100990569445192064567307041002",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "40380869235216625717296601204704413215735530626882135230693823362552484855508",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "4245751157938905689397184705633683893932492370323323780371834663438472308145",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "8252156875535418429533049587170755750275631534314711502253775796882240991261",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "32910829712934971129644416249914075073083903821282503505466324428991624789936",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "49412601297460128335642438246716127241669915737656789613664349252868389975962",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "841661305510340459373323516098909074520942972558284146843779636353111592117",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "37926489020263024391336570420006226544461516787280929232555625742588667303947",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "18433043696013996573551852847056868761017170818820490351056924728720017242180",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "45376910275288438312773930242803223482318753992595269901397542214841496212310",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "47854349410014339708332226068958253098964727682486278458389508597930796651514",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "32638426693771251366613055506166587312642876874690861030672730491779486904360",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "19105439281696418043426755774110765432959446684037017837894045255490581318047",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "13484299981373196201166722380389594773562113262309564134825386266765751213853",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "63360321133852659797114062808297090090814531427710842859827725871241144161",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "42427543035537409467993338717379268954936885184662765745740070438835506287271",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "149101987103211771991327927827692640556911620408176100290586418839323044234",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "8341764062226826803887898710015561861526081583071950015446833446251359696930",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "45635980415044299013530304465786867101223925975971912073759959440335364441441",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "49833261156201520743834327917353893365097424877680239796845398698940689734850",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "26764715016591436228000634284249890185894507497739511725029482580508707525029",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "25054530812095491217523557726611612265064441619646263299990388543372685322499",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "47654590955096246997622155031169641628093104787883934397920286718814889326452",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "16463825890556752307085325855351334996898686633642574805918056141310194135796",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "17473961341633494489168064889016732306117097771640351649096482400214968053040",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "49914603434867854893558366922996753035832008639512305549839666311012232077468",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "17122578514152308432111470949473865420090463026624297565504381163777697818362",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "34870689836420861427379101859113225049736283485335674111421609473028315711541",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "4622082908476410083286670201138165773322781640914243047922441301693321472984",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "6079244375752010013798561155333454682564824861645642293573415833483620500976",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "2635090520059500019661864086615522409798872905401305311748231832709078452746",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "19070766579582338321241892986615538320421651429118757507174186491084617237586",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "12622420533971517050761060317049369208980632120901481436392835424625664738526",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "8965101225657199137904506150282256568170501907667138404080397024857524386266",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "27085091008069524593196374148553176565775450537072498305327481366756159319838",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "45929056591150668409624595495643698205830429971690813312608217341940499221218",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "50361689160518167880500080025023064746137161030119436080957023803101861300846",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "6722586346537620732668048024627882970582133613352245923413730968378696371065",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "7340485916200743279276570085958556798507770452421357119145466906520506506342",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "25946733168219652706630789514519162148860502996914241011500280690204368174083",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "9962367658743163006517635070396368828381757404628822422306438427554934645464",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "7221669722700687417346373353960536661883467014204005276831020252277657076044",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "21487980358388383563030903293359140836304488103090321183948009095669344637431",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "44389482047246878765773958430749333249729101516826571588063797358040130313157",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "32887270862917330820874162842519225370447850172085449103568878409533683733185",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "15453393396765207016379045014101989306173462885430532298601655955681532648226",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5478929644476681096437469958231489102974161353940993351588559414552523375472",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "41981370411247590312677561209178363054744730805951096631186178388981705304138",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "3474136981645476955784428843999869229067282976757744542648188369810577298585",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "26251477770740399889956219915654371915771248171098220204692699710414817081869",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "51916561889718854106125837319509539220778634838409949714061033196765117231752",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "25355145802812435959748831835587713214179184608408449220418373832038339021974",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "31950684570730625275416731570246297947385359051792335826965013637877068017530",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "40966378914980473680181850710703295982197782082391794594149984057481543436879",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "1141315130963422417761731263662398620858625339733452795772225916965481730059",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "9812100862165422922235757591915383485338044715409891361026651619010947646011",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "25276091996614379065765602410190790163396484122487585763380676888280427744737",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "18512694312063606403196469408971540495273694846641903978723927656359350642619",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5791584766415439694303685437881192048262049244830616851865505314899699012588",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "34501536331706470927069149344450300773777486993504673779438188495686129846168",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "10797737565565774079718466476236831116206064650762676383469703413649447678207",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "42599392747310354323136214835734307933597896695637215127297036595538235868368",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "1336670998775417133322626564820911986969949054454812685145275612519924150700",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "2630141283339761901081411552890260088516693208402906795133548756078952896770",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5206688943117414740600380377278238268309952400341418217132724749372435975215",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "10739264253827005683370721104077252560524362323422172665530191908848354339715",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "48010640624945719826344492755710886355389194986527731603685956726907395779674",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "47880724693177306044229143357252697148359033158394459365791331000715957339701",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "51658938856669444737833983076793759752280196674149218924101718974926964118996",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "27558055650076329657496888512074319504342606463881203707330358472954748913263",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "38886981777859313701520424626728402175860609948757992393598285291689196608037",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "17152756165118461969542990684402410297675979513690903033350206658079448802479",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "43766946932033687220387514221943418338304186408056458476301583041390483707207",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "24324495647041812436929170644873622904287038078113808264580396461953421400343",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "6935839211798937659784055008131602708847374430164859822530563797964932598700",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "42126767398190942911395299419182514513368023621144776598842282267908712110039",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5702364486091252903915715761606014714345316580946072019346660327857498603375",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "28184981699552917714085740963279595942132561155181044254318202220270242523053",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "27078204494010940048327822707224393686245007379331357330801926151074766130790",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "5004172841233947987988267535285080365124079140142987718231874743202918551203",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "7974360962120296064882769128577382489451060235999590492215336103105134345602",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "48062035869818179910046292951628308709251170031813126950740044942870578526376",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "26361151154829600651603985995297072258262605598910254660032612019129606811983",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "46973867849986280770641828877435510444176572688208439836496241838832695841519",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "1219439673853113792340300173186247996249367102884530407862469123523013083971",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "8063356002935671186275773257019749639571745240775941450161086349727882957042",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "8815571992701260640209942886673939234666734294275300852283020522390608544536",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "36384568984671043678320545346945893232044626942887414733675890845013312931948",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "7493936589040764830842760521372106574503511314427857201860148571929278344956",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "26516538878265871822073279450474977673130300973488209984756372331392531193948",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "3872858659373466814413243601289105962248870842202907364656526273784217311104",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "8291822807524000248589997648893671538524566700364221355689839490238724479848",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "32842548776827046388198955038089826231531188946525483251252938248379132381248",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "10749428410907700061565796335489079278748501945557710351216806276547834974736",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "43342287917341177925402357903832370099402579088513884654598017447701677948416",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "29658571352070370791360499299098360881857072189358092237807807261478461425147",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "7805182565862454238315452208989152534554369855020544477885853141626690738363",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "30699555847500141715826240743138908521140760599479365867708690318477369178275",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
        vec![
            F::from_str(
                "1231951350103545216624376889222508148537733140742167414518514908719103925687",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "24784260089125933876714702247471508077514206350883487938806451152907502751770",
            )
            .map_err(|_| ())
            .unwrap(),
            F::from_str(
                "36563542611079418454711392295126742705798573252480028863133394504154697924536",
            )
            .map_err(|_| ())
            .unwrap(),
        ],
    ];
    let full_rounds = 8;
    let total_rounds = 37;
    let partial_rounds = total_rounds - full_rounds;
    PoseidonParameters::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds,
        ark,
    )
    
}

use ark_sponge::poseidon::{
    round_constants::round_constants,
    round_constants::round_constants_4,
    mds_matrix::mds_matrix,
};


pub fn poseidon_parameters_for_encryption<F: PrimeField>() -> PoseidonParameters<F> {
    let alpha = 17;
    let mds = mds_matrix();
    let ark = round_constants_4();
    let full_rounds = 8;
    let partial_rounds =  59;
    
    let mds_vec : Vec<_> = mds.iter().map(|&e| e.iter().map(|&t| F::from_be_bytes_mod_order(t.into_repr().to_bytes_be().as_slice())).collect()).collect();
    let ark_vec : Vec<_> = ark.iter().map(|&e| e.iter().map(|&t| F::from_be_bytes_mod_order(t.into_repr().to_bytes_be().as_slice())).collect()).collect();

    PoseidonParameters::new(
        full_rounds,
        partial_rounds,
        alpha,
        mds_vec,
        ark_vec,
    )

}


//== poseidon with sponge by zeroknight
pub type PoseidonParam = PoseidonParameters<Fr>;
pub type SPNGFunction = PoseidonSponge<Fr>;
pub type SPNGInput = Vec<u8>;
pub type SPNGOutput = Vec<Fr>;
pub type SPNGParam = <SPNGFunction as CryptographicSponge>::Parameters;

#[derive(Clone)]
pub struct SPNGCircuit {
    pub param: SPNGParam,
    pub input: SPNGInput,
    pub output: SPNGOutput,
}

impl ConstraintSynthesizer<Fr> for SPNGCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let pos_param_var = PoseidonSpongeVar::<Fr>::new(cs.clone(), &self.param);

        spng_circuit_helper(self.input, &self.output, cs, pos_param_var)?;

        Ok(())
    }
}

fn spng_circuit_helper(
    input: SPNGInput,
    output: &SPNGOutput,
    cs: ConstraintSystemRef<Fr>,
    pos_param_var: PoseidonSpongeVar<Fr>, ) -> Result<(), SynthesisError> 
{
    let absorb1 = input.clone();
    let absorb1_var: Vec<_> = absorb1.iter()
                .map(|v| UInt8::new_witness(ark_relations::ns!(cs, "absorb1"),
                                                    || Ok(*v)).unwrap()).collect();
    
    let sponge_params = poseidon_parameters_for_test_s::<Fr>();

    //sponge
    let mut native_sponge = PoseidonSponge::<Fr>::new(&sponge_params);
    let mut constraint_sponge = pos_param_var;

    native_sponge.absorb(&absorb1);
    constraint_sponge.absorb(&absorb1_var).unwrap();

    let squeeze2 = constraint_sponge.squeeze_field_elements(SIZEOFOUTPUT).unwrap();
    let outputVar: Vec<_> = output.iter()
                            .map(|v| FpVar::new_input(ark_relations::ns!(cs, "absorb1"), 
                                                || Ok(*v)).unwrap()).collect();
    squeeze2.enforce_equal(&outputVar).unwrap();
    Ok(())
}

//==========================================//
pub type SPNGMpcFunction<F> = PoseidonSponge<F>;
pub type SPNGMpcParam<F> = <SPNGMpcFunction<F> as CryptographicSponge>::Parameters; 
pub type SPNGMpcInput<F> = Vec<F>;
pub type SPNGMpcOutput<F> = Vec<F>;

//pub struct SPNGMpcCircuit<F, C> 
//    where F: PrimeField, C: PrimeField,
#[derive(Clone)]
pub struct SPNGMpcCircuit<F> 
    where F: PrimeField
{
    pub param: SPNGMpcParam<F>,
    pub input: SPNGMpcInput<F>,
    pub output: SPNGMpcOutput<F>,
}

//impl<F:PrimeField, C: PrimeField> ConstraintSynthesizer<F> for SPNGMpcCircuit<F,C> {
impl<F:PrimeField> ConstraintSynthesizer<F> for SPNGMpcCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let pos_param_var = PoseidonSpongeVar::<F>::new(cs.clone(), &self.param);
        
        spng_mpc_circuit_helper(self.input, &self.output, cs, pos_param_var)?;

        Ok(())
    }
}

//fn spng_mpc_circuit_helper<F,C>(
fn spng_mpc_circuit_helper<F>(
    input: SPNGMpcInput<F>,
    output: &SPNGMpcOutput<F>,
    cs: ConstraintSystemRef<F>,
    pos_param_var: PoseidonSpongeVar<F>) -> Result<(), SynthesisError>
where F:PrimeField,
{
    let absorb1 = input.clone();
    let absorb_val : Vec<u8> = input.iter().map(|t| t.into_repr().to_bytes_be()[31]).collect();    // only u8 works..
//    let absorb3 : Vec<u8> = absorb2.iter().flat_map(|f| f.iter().map(|a| *a)).collect();   //Vec<Vec<u8>>
    let absorb1_var : Vec<_> = absorb1.iter()
                .map(|v| {
                    //let mut val = v.into_repr().to_bytes_be()[31];  // 256 bits.. big endian..
                    //UInt8::new_witness(ark_relations::ns!(cs, "absorb1"), || Ok(val))
                    
                    //cs.new_witness_variable(|| Ok(*v) ).unwrap()
                    FpVar::new_witness(ark_relations::ns!(cs, "absorb1"), 
                                        || Ok(*v)).unwrap()
                }).collect();
    let absorb_var: Vec<_> = absorb_val.iter()
                .map(|v| UInt8::new_witness(ark_relations::ns!(cs, "absorb1"), 
                                                    || Ok(*v)).unwrap()).collect();
    
    let sponge_params = poseidon_parameters_for_test_s::<F>();

    // sponge
    let mut native_sponge = PoseidonSponge::<F>::new(&sponge_params);
    let mut constraint_sponge = pos_param_var;

    // absorb
    native_sponge.absorb(&absorb_val);
    constraint_sponge.absorb(&absorb1_var).unwrap(); // !! should be absorb1_var : FpVar

    let squeeze2 = constraint_sponge.squeeze_field_elements(SIZEOFOUTPUT).unwrap();
    let outputVar: Vec<_> = output.iter()
                            .map(|v| FpVar::new_input(ark_relations::ns!(cs, "absorb1"), 
                            || Ok(*v)).unwrap()).collect();
    squeeze2.enforce_equal(&outputVar).unwrap();
    
    Ok(())

}

pub type PoseidonMpcFunction<F> = PoseidonSponge<F>;
pub type PoseidonMpcParam<F> = <PoseidonMpcFunction<F> as CryptographicSponge>::Parameters;
pub type PoseidonMpcInput<F> = Vec<F>;
pub type PoseidonMpcOutput<F> = Vec<F>;

#[derive(Clone)]
pub struct PoseidonMpcCircuit<F:PrimeField>
{
    pub param: Option<PoseidonMpcParam<F>>,
    pub input: Option<PoseidonMpcInput<F>>,
    pub output: Option<PoseidonMpcOutput<F>>,
}

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF> for PoseidonMpcCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {

        //let input_field_val = self.input.clone().unwrap();
        //let input_val : Vec<u8> = self.input.clone().unwrap()
        //                                    .iter().map(|t| t.into_repr().to_bytes_be()[31]).collect();
        
        let pos_param_var = PoseidonSpongeVar::<ConstraintF>::new(cs.clone(), &self.param.unwrap());
        let input_var: Vec<_> = self.input.unwrap().iter()
                                .map(|v| {
                                    FpVar::new_witness(ark_relations::ns!(cs, "input_var"), 
                                                    || Ok(*v)).unwrap()
                                }).collect();
        
        let sponge_params = poseidon_parameters_for_encryption::<ConstraintF>();
        
        let mut native_sponge = PoseidonSponge::<ConstraintF>::new(&sponge_params);
        let mut constraint_sponge = pos_param_var;
        
        //native_sponge.absorb(&input_field_val);
        constraint_sponge.absorb(&input_var).unwrap();
        let squeeze = constraint_sponge.squeeze_field_elements(SIZEOFOUTPUT).unwrap();
        
        let value = squeeze.value().unwrap();
        println!("Constraint_sponage : {:?}",value);

        let outputvar: Vec<_> = self.output.unwrap().iter()
                                .map(|v| FpVar::new_input(ark_relations::ns!(cs, "absorb1"), 
                                || Ok(*v)).unwrap()).collect();
        
        Ok(())
    }
}

fn poseidon_mpc_circuit_helper<F>(
    input: PoseidonMpcInput<F>,
    output: &PoseidonMpcOutput<F>,
    cs: ConstraintSystemRef<F>,
    pos_param_var: PoseidonSpongeVar<F> ) -> Result<(), SynthesisError>
where F:PrimeField,
{
    let absorb1 = input.clone();
    let absrob_val: Vec<u8> = input.iter().map(|t| t.into_repr().to_bytes_be()[31]).collect();
    let absorb1_var: Vec<_> = absorb1.iter()
                            .map(|v| {
                                FpVar::new_witness(ark_relations::ns!(cs,"absorb1"), 
                                        || Ok(*v)).unwrap()
                            }).collect();
    
    let sponge_params = poseidon_parameters_for_encryption::<F>();

    //sponge
    let mut native_sponge = PoseidonSponge::<F>::new(&sponge_params);
    let mut constraint_sponge = pos_param_var;
    
    //absorb
    native_sponge.absorb(&absrob_val);
    constraint_sponge.absorb(&absorb1_var).unwrap();

    let squeeze2 = constraint_sponge.squeeze_field_elements(SIZEOFOUTPUT).unwrap();
    let outputVar: Vec<_> = output.iter()
                            .map(|v| FpVar::new_input(ark_relations::ns!(cs,"absorb1_out"),
                                    || Ok(*v)).unwrap()).collect();

    Ok(())
}

#[test]
fn test_vec() {
    let mut a = Vec::new();

    a.push(ark_ed_on_bls12_381::Fr::from_be_bytes_mod_order(&[2u8]));
    println!("A : {:?}", a);

    let mut b = a.pop().unwrap();
    println!("B : {:?}", b.into_repr().to_bytes_be()[31]);

    let aa = ark_ed_on_bls12_381::Fr::from_be_bytes_mod_order(&[2u8]);
    let bb = ark_ed_on_bls12_381::Fr::from_be_bytes_mod_order(&[15u8]);

    let cc = aa * bb;

    let c = cc.into_repr().to_bytes_be()[31];
    println!("C: {:?}", c);

}

#[test]
fn test_poseidon_hash() {

    type baseFr = ark_bls12_381::Fr;

    const INPTEXT: &str = "Hello, Radius";
    
    let input = INPTEXT.as_bytes().to_vec();
    
    let mut field_vec_input : Vec::<baseFr> = input.iter().map(|v| baseFr::from(*v)).collect();
    println!("input_u8: {:?}", input);
    println!("field_vec: {:?}", field_vec_input);

    
    // using native ark_bls12_381
    let parameter = poseidon_parameters_for_encryption::<baseFr>();
    let mut native_sponge = PoseidonSponge::<baseFr>::new(&parameter);
    native_sponge.absorb(&field_vec_input);
    let native_out = native_sponge.squeeze_native_field_elements(SIZEOFOUTPUT);
    println!("parameter 1st in ark : {:?}", parameter.ark[0][0]);
    println!("native_out : {:?}", native_out);

    // using MpcField <- currently panicking!!
    use mpc_algebra::wire::MpcField;
    use mpc_algebra::PairingShare;
    use ark_ec::PairingEngine;
    type pengine = ark_bls12_381::Bls12_381; // PairingEngine
    type sharing = mpc_algebra::AdditivePairingShare<ark_bls12_381::Bls12_381>;

/*
    let mpc_parameter = poseidon_parameters_for_encryption::< MpcField::<<pengine as PairingEngine>::Fr, <sharing as PairingShare<pengine>>::FrShare>>();
    let mut mpc_sponge = PoseidonSponge::< MpcField::<<pengine as PairingEngine>::Fr, <sharing as PairingShare<pengine>>::FrShare>>::new(&mpc_parameter);
    mpc_sponge.squeeze_native_field_elements(SIZEOFOUTPUT);
    let mpc_out = mpc_sponge.squeeze_native_field_elements(SIZEOFOUTPUT);
    println!("[mpc] parameter 1st in ark : {:?}", mpc_parameter.ark[0][0]);
    println!("[mpc] mpc_out : {:?}", mpc_out);
*/

    let rng = &mut test_rng();
    let test1 = MpcField::<<pengine as PairingEngine>::Fr, <sharing as PairingShare<pengine>>::FrShare>::rand(rng);
    let input_test1 = test1.unwrap_as_public();
    println!("input_test1: {:?}", input_test1);

    let rep = input_test1.into_repr().to_bytes_be();
    println!("rep: {:?}", rep);

    let mut repr2 = ark_bls12_381::Fr::from_be_bytes_mod_order(rep.as_slice());
    println!("repr2: {:?}", repr2);


}