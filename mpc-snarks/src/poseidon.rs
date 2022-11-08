use ark_crypto_primitives::{
    crh::poseidon::{PoseidonCRH, Poseidon, PoseidonRoundParams},
    crh::poseidon::sbox::PoseidonSbox,
    crh::FixedLengthCRH,
};

// constraints
use ark_crypto_primitives::{
    crh::poseidon::constraints::PoseidonRoundParamsVar,
};

use ark_ff::{Field, PrimeField};

use ark_relations::{
    r1cs::{SynthesisError,
    ConstraintSystemRef,
    ConstraintSynthesizer},   // ../snark/relations
};

// [Important!!] ark-bls12-377 and bls12-381 doesn't work!!!! by zeroknight
use ark_ed_on_bls12_381::Fq;


pub type CRHFunction = PoseidonCRH<Fq, PParams>;

pub type CRHParam = <CRHFunction as FixedLengthCRH>::Parameters;
pub type CRHInput = [u8; 32];
pub type CRHOutput = <CRHFunction as FixedLengthCRH>::Output;

#[derive(Clone)]
pub struct PoseidonCircuit<F: Field> {
    pub a: Option<F>,
    pub param: CRHParam,
    pub input: CRHInput,
    pub output: CRHOutput,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for PoseidonCircuit<ConstraintF> {
    fn generate_constraints (
        self,
        cs: ConstraintSystemRef<ConstraintF>,
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

    println!("{}", out);



}

#[test]
fn test_poseidon() {
    tryout_poseidon();
}