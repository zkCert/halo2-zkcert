use halo2_rsa::big_uint::BigUintInstructions;
use halo2_rsa::{
    RSAConfig,
    AssignedBigUint, AssignedRSAPubE, AssignedRSAPublicKey, AssignedRSASignature, BigUintConfig,
    Fresh, RSAInstructions, RSAPubE, RSAPublicKey, RSASignature,
};
use halo2_sha256_unoptimized::Sha256Chip;
use halo2_base::halo2_proofs::plonk::Error;
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::GateChip, range::RangeChip, GateInstructions, RangeInstructions},
    utils::{biguint_to_fe, fe_to_biguint, ScalarField, BigPrimeField},
    AssignedValue, Context,
};

use num_bigint::BigUint;

#[derive(Clone, Debug)]
pub struct ZKCertChip<F: BigPrimeField, G: ScalarField> {
    rsa_config: RSAConfig<F>,
    sha256_config: Sha256Chip<G>
}

impl<F: BigPrimeField, G: ScalarField> ZKCertChip<F, G> {
    pub fn construct(
        rsa_config: RSAConfig<F>,
        sha256_config: Sha256Chip<G>,
    ) -> Self {
        Self {
            rsa_config,
            sha256_config
        }
    }
}
