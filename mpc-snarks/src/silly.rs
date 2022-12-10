use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

#[derive(Clone)]
pub struct MySillyCircuit<F: Field> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);
            Ok(a)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}

/*
//====================== zeroknight ===============//
use ark_sponge::poseidon::{PoseidonSponge};
use ark_sponge::CryptographicSponge;

pub type PoseidonMpcFunction<F> = PoseidonSponge<F>;
pub type PoseidonMpcParam<F> = <PoseidonMpcFunction<F> as CryptographicSponge>::Parameters;
pub type PoseidonMpcInput<F> = Vec<F>;
pub type PoseidonMpcOutput<F> = Vec<F>;

#[derive(Clone)]
pub struct PoseidonMpcCircuit<F:Field>
{
    pub param: Option<PoseidonMpcParam<F::BasePrimeField>>,
    pub input: Option<PoseidonMpcInput<F>>,
    pub output: Option<PoseidonMpcOutput<F>>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for PoseidonMpcCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}
/*
impl<F: Field> ConstraintSynthesizer<F> for PoseidonMpcCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        //let pos_param_var = PoseidonSpongeVar::<F>::new(cs.clone(), &self.param);
        Ok(())
    }
}
*/
*/