use halo2_base::{
    gates::{circuit::CircuitBuilderStage, GateInstructions},
    halo2_proofs::{
        halo2curves::bn256::Bn256,
        poly::kzg::commitment::ParamsKZG,
    },
    halo2_proofs::plonk::Error,
    QuantumCell::{Existing, Constant},
    utils::{ScalarField, BigPrimeField},
    AssignedValue, Context
};
use halo2_rsa::{
    big_uint::BigUintInstructions,
    RSAConfig,
    AssignedRSAPublicKey, AssignedRSASignature, RSAInstructions
};
use halo2_sha256_unoptimized::Sha256Chip;
use snark_verifier_sdk::{
    SHPLONK,
    halo2::aggregation::{AggregationConfigParams, VerifierUniversality, AggregationCircuit},
    Snark,
};
use itertools::Itertools;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub enum SignatureAlgorithm<F: ScalarField + BigPrimeField> {
    RSA(RSAConfig<F>),
    // Currently only RSA, in the future, we can include ECDSA and other signature algorithms for certificate verification
    // Full list of valid signature algorithms https://github.com/rusticata/x509-parser/blob/master/src/verify.rs
}

#[derive(Clone, Debug)]
pub enum HashFunction<F: ScalarField + BigPrimeField> {
    SHA256(Sha256Chip<F>),
    // Currently only SHA256, in the future, we can include other hash functions for certificate verification
}

#[derive(Clone, Debug)]
pub struct X509CertificateVerifierChip<F: BigPrimeField + ScalarField> {
    signature_algorithm: SignatureAlgorithm<F>,
    hash_function: HashFunction<F>,
}

impl<F: BigPrimeField + ScalarField> X509CertificateVerifierChip<F> {
    pub fn construct(
        signature_algorithm: SignatureAlgorithm<F>,
        hash_function: HashFunction<F>,
    ) -> Self {
        Self {
            signature_algorithm,
            hash_function,
        }
    }

    pub fn verify_pkcs1_sha256_with_rsa(
        &self,
        ctx: &mut Context<F>,
        public_key: &AssignedRSAPublicKey<F>,
        msg: &[u8],
        signature: &AssignedRSASignature<F>,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
        let SignatureAlgorithm::RSA(rsa_config) = &self.signature_algorithm;
        let HashFunction::SHA256(sha256_config) = &self.hash_function;

        // Adapted from halo2-rsa https://github.com/zkemail/halo2-rsa/blob/main/src/lib.rs
        let biguint = rsa_config.biguint_config();
        // TODO: keep precomputed len 0 for now
        let result = sha256_config.clone().digest(ctx, msg, None)?;
        let mut hashed_bytes = result.output_bytes;
        hashed_bytes.reverse();
        let bytes_bits = hashed_bytes.len() * 8;
        let limb_bits = biguint.limb_bits();
        let limb_bytes = limb_bits / 8;
        let mut hashed_u64s = vec![];
        let bases = (0..limb_bytes)
            .map(|i| F::from(1u64 << (8 * i)))
            .map(Constant)
            .collect_vec();
        for i in 0..(bytes_bits / limb_bits) {
            let left = hashed_bytes[limb_bytes * i..limb_bytes * (i + 1)]
                .iter()
                .map(|x| Existing(*x))
                .collect_vec();
            let sum = biguint.gate().inner_product(ctx, left, bases.clone());
            hashed_u64s.push(sum);
        }
        let is_sign_valid =
            rsa_config.verify_pkcs1v15_signature(ctx, public_key, &hashed_u64s, signature)?;

        hashed_bytes.reverse();
        Ok((is_sign_valid, hashed_bytes))
    }
}

#[derive(Clone, Debug)]
pub struct X509VerifierAggregationCircuit {
    pub aggregation_circuit: AggregationCircuit,
}

impl X509VerifierAggregationCircuit {
    pub fn new(
        stage: CircuitBuilderStage,
        config_params: AggregationConfigParams,
        params: &ParamsKZG<Bn256>,
        snarks: Vec<Snark>,
        universality: VerifierUniversality
    ) -> Self {
        // NOTE: only accept 4 snarks into this aggregation circuit
        assert_eq!(snarks.len(), 4);
        let mut aggregation_circuit = AggregationCircuit::new::<SHPLONK>(
            stage,
            config_params,
            params,
            snarks.clone(),
            universality,
        );

        for i in 0..snarks[0].instances.len() {
            snarks[0].instances[i].iter().zip(snarks[1].instances[i].iter()).map(|(x, y)| {
                let x = aggregation_circuit.builder.pool(0).threads[0].load_witness(*x);
                let y = aggregation_circuit.builder.pool(0).threads[0].load_witness(*y);
                aggregation_circuit.builder.pool(0).threads[0].constrain_equal(&x, &y);
            }).collect_vec();
        }
        for i in 0..snarks[2].instances.len() {
            snarks[2].instances[i].iter().zip(snarks[3].instances[i].iter()).map(|(x, y)| {
                let x = aggregation_circuit.builder.pool(0).threads[0].load_witness(*x);
                let y = aggregation_circuit.builder.pool(0).threads[0].load_witness(*y);
                aggregation_circuit.builder.pool(0).threads[0].constrain_equal(&x, &y);
            }).collect_vec();
        }

        Self {
            aggregation_circuit
        }
    }
}