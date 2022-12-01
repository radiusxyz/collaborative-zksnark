use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::encryption::elgamal::{
    Ciphertext, ElGamal, Parameters, Plaintext, PublicKey, Randomness,
};
use crate::encryption::AsymmetricEncryptionGadget;
use ark_ec::ProjectiveCurve;
use ark_ff::{
    fields::{Field, PrimeField},
    to_bytes, Zero,
};
use ark_std::{borrow::Borrow, marker::PhantomData, vec::Vec};

pub type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

#[derive(Clone, Debug)]
pub struct RandomnessVar<F: Field>(Vec<UInt8<F>>);

impl<C, F> AllocVar<Randomness<C>, F> for RandomnessVar<F>
where
    C: ProjectiveCurve,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Randomness<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let r = to_bytes![&f().map(|b| b.borrow().0).unwrap_or(C::ScalarField::zero())].unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct ParametersVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    generator: GG,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GG::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self {
            generator,
            _curve: PhantomData,
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct PlaintextVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub plaintext: GG,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Plaintext<C>, ConstraintF<C>> for PlaintextVar<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Plaintext<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let plaintext = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            plaintext,
            _curve: PhantomData,
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct PublicKeyVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub pk: GG,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pk = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            pk,
            _curve: PhantomData,
        })
    }
}

#[derive(Derivative, Debug)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct OutputVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub c1: GG,
    pub c2: GG,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Ciphertext<C>, ConstraintF<C>> for OutputVar<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Ciphertext<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let prep = f().map(|g| *g.borrow());
        let c1 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().0), mode)?;
        let c2 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().1), mode)?;
        Ok(Self {
            c1,
            c2,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> EqGadget<ConstraintF<C>> for OutputVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.c1.is_eq(&other.c1)?.and(&self.c2.is_eq(&other.c2)?)
    }
}

pub struct ElGamalEncGadget<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    _group_var: PhantomData<*const GG>,
}

impl<C, GG> AsymmetricEncryptionGadget<ElGamal<C>, ConstraintF<C>> for ElGamalEncGadget<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField,
{
    type OutputVar = OutputVar<C, GG>;
    type ParametersVar = ParametersVar<C, GG>;
    type PlaintextVar = PlaintextVar<C, GG>;
    type PublicKeyVar = PublicKeyVar<C, GG>;
    type RandomnessVar = RandomnessVar<ConstraintF<C>>;

    fn encrypt(
        parameters: &Self::ParametersVar,
        message: Vec<Self::PlaintextVar>,
        randomness: &Self::RandomnessVar,
        public_key: &Self::PublicKeyVar,
    ) -> Result<Vec<Self::OutputVar>, SynthesisError> {
        let msg_iter = message.iter();
        // flatten randomness to little-endian bit vector
        let randomness = randomness
            .0
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();


        let mut cipher_vec = vec!();
        for msg in msg_iter {
            // compute s = randomness*pk
            let s = public_key.pk.clone().scalar_mul_le(randomness.iter())?;

            // compute c1 = randomness*generator
            let c1 = parameters
            .generator
            .clone()
            .scalar_mul_le(randomness.iter())?;

            // compute c2 = m + s
            let c2 = msg.plaintext.clone() + s;
            cipher_vec.push(Self::OutputVar {
                c1,
                c2,
                _curve: PhantomData,
            })
        }

        Ok(cipher_vec)
    }
}

#[cfg(test)]
mod test {
    use crate::encryption::constraints::AsymmetricEncryptionGadget;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_std::{test_rng, UniformRand, vec::Vec};

    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};

    use crate::encryption::elgamal::{constraints::ElGamalEncGadget, ElGamal, Randomness};
    use crate::encryption::sub_strings;
    use crate::encryption::AsymmetricEncryptionScheme;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_elgamal_gadget() {
        let rng = &mut test_rng();

        type MyEnc = ElGamal<JubJub>;
        type MyGadget = ElGamalEncGadget<JubJub, EdwardsVar>;

        // compute primitive result
        let parameters = MyEnc::setup(rng).unwrap();
        let (pk, _) = MyEnc::keygen(&parameters, rng).unwrap();

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
        let primitive_result_vec = MyEnc::encrypt(&parameters, &pk, msg_affine_vec.clone(), &randomness).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let randomness_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::RandomnessVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || Ok(&randomness),
            )
            .unwrap();
        let parameters_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "gadget_parameters"),
                &parameters,
            )
            .unwrap();
        let mut msg_var_vec : Vec<<MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PlaintextVar> = vec!();
        let msg_affine_iter = msg_affine_vec.iter();
        for msg_affine in msg_affine_iter {
            let msg_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PlaintextVar::new_witness(
                ark_relations::ns!(cs, "gadget_message"),
                || Ok(msg_affine),
            )
            .unwrap();
            msg_var_vec.push(msg_var);
        }
        let pk_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PublicKeyVar::new_witness(
                ark_relations::ns!(cs, "gadget_public_key"),
                || Ok(&pk),
            )
            .unwrap();

        // use gadget
        let result_var_vec =
            MyGadget::encrypt(&parameters_var, msg_var_vec, &randomness_var, &pk_var).unwrap();

        // check that result equals expected ciphertext in the constraint system
        let mut expected_var_vec = vec!();
        let primitive_iter = primitive_result_vec.iter();

        for primitive_result in primitive_iter {
            let expected_var = <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::OutputVar::new_input(
                ark_relations::ns!(cs, "gadget_expected"),
                || Ok(primitive_result),
            )
            .unwrap();
            expected_var_vec.push(expected_var);
        }

        assert_eq!(expected_var_vec.len(), result_var_vec.len());

        for i in 0..expected_var_vec.len() {
            expected_var_vec[i].enforce_equal(&result_var_vec[i]).unwrap(); 
        }
        
        // assert_eq!(primitive_result.0.into_projective(), result_var.c1.value().unwrap());
        // assert_eq!(primitive_result.1.into_projective(), result_var.c2.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
