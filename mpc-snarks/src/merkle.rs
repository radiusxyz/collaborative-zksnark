use ark_crypto_primitives::crh::pedersen::{CRH, Parameters};

pub struct MerkleTreeVerification {
    pub leaf_crh_params: Parameters,
    //pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,
}

#[test]
fn test_merkle_tree() {

}