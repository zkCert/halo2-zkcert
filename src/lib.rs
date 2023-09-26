use halo2_rsa::big_uint::BigUintInstructions;
// use ark_std::{end_timer, start_timer};
use halo2_rsa::{
    RSAConfig,
    AssignedBigUint, AssignedRSAPubE, AssignedRSAPublicKey, AssignedRSASignature, BigUintConfig,
    Fresh, RSAInstructions, RSAPubE, RSAPublicKey, RSASignature,
};
use halo2_sha256_unoptimized::Sha256Chip;
use halo2_base::halo2_proofs::plonk::Error;
use halo2_base::QuantumCell::{Existing, Constant};
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage, BaseCircuitParams},
        flex_gate::GateChip, range::RangeChip, GateInstructions, RangeInstructions},
    utils::{biguint_to_fe, fe_to_biguint, ScalarField, BigPrimeField},
    AssignedValue, Context,
    utils::fs::gen_srs
};
use snark_verifier_sdk::halo2::aggregation::{AggregationConfigParams, VerifierUniversality};
use snark_verifier_sdk::SHPLONK;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    Snark,
};
use itertools::Itertools;

use num_bigint::BigUint;

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
        let rsa_config = match &self.signature_algorithm {
            SignatureAlgorithm::RSA(config) => {
                config
            }
        };
        let sha256_config = match &self.hash_function {
            HashFunction::SHA256(config) => {
                config
            }
        };

        // Adapted from halo2-rsa https://github.com/zkemail/halo2-rsa/blob/main/src/lib.rs
        let biguint = rsa_config.biguint_config();
        let result = sha256_config.clone().digest(ctx, msg)?;
        let mut hashed_bytes = result.output_bytes;
        hashed_bytes.reverse();
        let bytes_bits = hashed_bytes.len() * 8;
        let limb_bits = biguint.limb_bits();
        let limb_bytes = limb_bits / 8;
        let mut hashed_u64s = vec![];
        let bases = (0..limb_bytes)
            .map(|i| F::from((1u64 << (8 * i)) as u64))
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

#[cfg(test)]
mod test {
    use super::*;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
    use halo2_base::utils::testing::base_test;

    use rand::{thread_rng, Rng};
    use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::Read;
    use std::vec;
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::certificate::X509Certificate;
    use x509_parser::public_key::PublicKey;

    pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
        let issuer_public_key = issuer.public_key();
        cert.verify_signature(Some(&issuer_public_key)).is_ok()
    }

    macro_rules! impl_verify_pkcs1_sha256_with_rsa_test_circuit {
        ($verify_cert_path:expr, $issuer_cert_path: expr, $should_err: expr) => {
            // Read the PEM certificate from a file
            let mut cert_file = File::open($verify_cert_path).expect("Failed to open PEM file");
            let mut cert_pem_buffer = Vec::new();
            cert_file.read_to_end(&mut cert_pem_buffer).expect("Failed to read PEM file");

            // Parse the PEM certificate using x509-parser
            let cert_pem = parse_x509_pem(&cert_pem_buffer).expect("Failed to parse cert 3 PEM").1;
            let cert = cert_pem.parse_x509().expect("Failed to parse PEM certificate");

            // Extract the TBS (To-Be-Signed) data from the certificate 3
            let tbs = &cert.tbs_certificate.as_ref();
            // println!("TBS (To-Be-Signed): {:x?}", tbs);

            // Extract the signature from cert 3
            let signature_bytes = &cert.signature_value;
            let signature_bigint = BigUint::from_bytes_be(&signature_bytes.data);
            // println!("Signature: {:?}", signature_bigint);

            let mut issuer_cert_file = File::open($issuer_cert_path).expect("Failed to open cert 2PEM file");
            let mut issuer_cert_pem_buffer = Vec::new();
            issuer_cert_file.read_to_end(&mut issuer_cert_pem_buffer).expect("Failed to read cert 2 PEM file");

            // Parse the PEM certificate using x509-parser
            let issuer_cert_pem = parse_x509_pem(&issuer_cert_pem_buffer).expect("Failed to parse cert 3 PEM").1;
            let issuer_cert = issuer_cert_pem.parse_x509().expect("Failed to parse PEM certificate");
            
            // Extract the public key of cert 2
            let public_key_modulus = match issuer_cert.public_key().parsed().unwrap() {
                PublicKey::RSA(pub_key) => {
                    let modulus = BigUint::from_bytes_be(pub_key.modulus);
                    // println!("Public Key modulus: {:?}", modulus);
                    modulus
                },
                _ => panic!("Failed to grab modulus. Not RSA")
            };

            // // Verify Cert in Rust
            // let is_valid = check_signature(&cert, &issuer_cert);

            // Circuit inputs
            let k: usize = 18;
            let limb_bits = 64;
            let default_bits = 2048;
            let exp_bits = 5;
            let default_e = 65537 as u32;
            let max_byte_sizes = vec![1280];

            // Create test circuit
            base_test().k(k as u32).lookup_bits(k - 1).expect_satisfied(!$should_err).run(|ctx, range| {
                let range = range.clone();
                let bigint_chip = BigUintConfig::construct(range.clone(), limb_bits);
                let rsa_chip = RSAConfig::construct(bigint_chip, default_bits, exp_bits);
                let sha256_chip = Sha256Chip::construct(max_byte_sizes, range, true);
                let chip = X509CertificateVerifierChip::construct(
                    SignatureAlgorithm::RSA(rsa_chip.clone()),
                    HashFunction::SHA256(sha256_chip),
                );

                // Verify Cert
                let e_fix = RSAPubE::Fix(BigUint::from(default_e));
                let public_key = RSAPublicKey::new(public_key_modulus.clone(), e_fix);     // cloning might be slow
                let public_key = rsa_chip.assign_public_key(ctx, public_key).unwrap();

                let signature = RSASignature::new(signature_bigint.clone());             // cloning might be slow
                let signature = rsa_chip.assign_signature(ctx, signature).unwrap();

                let expected_hashed_msg = Sha256::digest(&tbs);
                let (is_valid, hashed_msg) =
                    chip.verify_pkcs1_sha256_with_rsa(ctx, &public_key, &tbs, &signature).unwrap();
                rsa_chip.biguint_config()
                    .gate()
                    .assert_is_const(ctx, &is_valid, &Fr::one());
                for i in 0..32 {
                    assert_eq!(&Fr::from(expected_hashed_msg[i] as u64), hashed_msg[i].value());
                }
            });
        };
    }
    
    
    #[test]
    #[ignore]
    fn test_verify_pkcs1_sha256_with_rsa1() {        
        let k: usize = 18;

        // Circuit inputs
        let limb_bits = 64;
        let default_bits = 2048;
        let exp_bits = 5;
        let default_e = 65537 as u32;
        let max_byte_sizes = vec![192];

        base_test().k(k as u32).lookup_bits(k - 1).run(|ctx, range| {
            let range = range.clone();
            let bigint_chip = BigUintConfig::construct(range.clone(), limb_bits);
            let rsa_chip = RSAConfig::construct(bigint_chip, default_bits, exp_bits);
            let sha256_chip = Sha256Chip::construct(max_byte_sizes, range, true);
            let chip = X509CertificateVerifierChip::construct(
                SignatureAlgorithm::RSA(rsa_chip.clone()),
                HashFunction::SHA256(sha256_chip),
            );

            let mut rng = thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, default_bits).expect("failed to generate a key");
            let public_key = RsaPublicKey::from(&private_key);
            let mut msg:[u8;128] = [0; 128];
            for i in 0..128 {
                msg[i] = rng.gen();
            }
            let expected_hashed_msg = Sha256::digest(&msg);
            let padding = PaddingScheme::PKCS1v15Sign {
                hash: Some(Hash::SHA2_256),
            };
            let mut sign = private_key
                .sign(padding, &expected_hashed_msg)
                .expect("fail to sign a hashed message.");
            sign.reverse();
            let sign_big = BigUint::from_bytes_le(&sign);
            let sign = rsa_chip.assign_signature(ctx, RSASignature::new(sign_big)).unwrap();
            let n_big =
                BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16)
                    .unwrap();
            let e_fix = RSAPubE::Fix(BigUint::from(default_e));
            let public_key = rsa_chip
                .assign_public_key(ctx, RSAPublicKey::new(n_big, e_fix)).unwrap();
            let (is_valid, hashed_msg) =
                chip.verify_pkcs1_sha256_with_rsa(ctx, &public_key, &msg, &sign).unwrap();
            rsa_chip.biguint_config()
                .gate()
                .assert_is_const(ctx, &is_valid, &Fr::one());
            for i in 0..32 {
                assert_eq!(&Fr::from(expected_hashed_msg[i] as u64), hashed_msg[i].value());
            }
        });
    }

    #[test]
    #[ignore]
    fn test_verify_pkcs1_sha256_with_rsa2() {
        impl_verify_pkcs1_sha256_with_rsa_test_circuit!(
            "./certs/cert_3.pem",
            "./certs/cert_2.pem",
            false
        );
    }

    #[test]
    #[ignore]
    fn test_verify_pkcs1_sha256_with_rsa3() {
        impl_verify_pkcs1_sha256_with_rsa_test_circuit!(
            "./certs/cert_2.pem",
            "./certs/cert_1.pem",
            false
        );
    }

    #[test]
    #[ignore]
    fn test_verify_pkcs1_sha256_with_rsa4() {
        impl_verify_pkcs1_sha256_with_rsa_test_circuit!(
            "./certs/cert_3.pem",
            "./certs/cert_1.pem",
            true
        );
    }

    #[test]
    fn test_aggregation() {
        
        fn generate_circuit() -> Snark {
            let k: usize = 18;
            let lookup_bits = k as usize - 1;

            // Circuit inputs
            let limb_bits = 64;
            let default_bits = 512;
            let exp_bits = 5;
            let default_e = 65537 as u32;
            let max_byte_sizes = vec![192];
    
            let builder = BaseCircuitBuilder::new(false);


            // Set all
            let circuit_params = BaseCircuitParams {
                k: k as usize,
                num_advice_per_phase: vec![40],
                num_lookup_advice_per_phase: vec![1],
                num_fixed: 1,
                lookup_bits: Some(lookup_bits),
                num_instance_columns: 1,
            };
            let mut builder = builder.use_params(circuit_params);
            

            // Set few
            // builder.set_k(k);
            // builder.set_lookup_bits(lookup_bits);
            // builder.set_instance_columns();

            let range = builder.range_chip();
            let ctx = builder.main(0);
            
            let bigint_chip = BigUintConfig::construct(range.clone(), limb_bits);
            let rsa_chip = RSAConfig::construct(bigint_chip, default_bits, exp_bits);
            let sha256_chip = Sha256Chip::construct(max_byte_sizes, range.clone(), true);
            let chip = X509CertificateVerifierChip::construct(
                SignatureAlgorithm::RSA(rsa_chip.clone()),
                HashFunction::SHA256(sha256_chip),
            );
    
            // Generate values to be fed into the circuit (Pure Rust)
            let mut rng = thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, default_bits).expect("failed to generate a key");
            let public_key = RsaPublicKey::from(&private_key);
            let mut msg:[u8;128] = [0; 128];
            for i in 0..128 {
                msg[i] = rng.gen();
            }
            let expected_hashed_msg = Sha256::digest(&msg);
            let padding = PaddingScheme::PKCS1v15Sign {
                hash: Some(Hash::SHA2_256),
            };
            let mut sign = private_key
                .sign(padding, &expected_hashed_msg)
                .expect("fail to sign a hashed message.");
            sign.reverse();
            let sign_big = BigUint::from_bytes_le(&sign);
            let n_big =
                BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16)
                    .unwrap();
            let e_fix = RSAPubE::Fix(BigUint::from(default_e));
            
            // Assign values to the circuit
            let sign = rsa_chip.assign_signature(ctx, RSASignature::new(sign_big)).unwrap();
            let public_key = rsa_chip
                .assign_public_key(ctx, RSAPublicKey::new(n_big, e_fix)).unwrap();
            
            let (is_valid, hashed_msg) =
                chip.verify_pkcs1_sha256_with_rsa(ctx, &public_key, &msg, &sign).unwrap();
            
            range.gate().assert_is_const(ctx, &is_valid, &Fr::one());

            // let x = ctx.load_witness(Fr::from(14));
            // range.gate().add(ctx, x, x);

            // Generate params
            println!("Generate params");
            let params = gen_srs(k as u32);
            
            // println!("Generating proving key");
            let pk = gen_pk(&params, &builder, None);
    
            // Generate proof
            println!("Generating proof");
            gen_snark_shplonk(&params, &pk, builder, None::<&str>)
        }
       
       println!("Generating dummy snark");
       let dummy_snark = generate_circuit();

        // Create an aggregation circuit using the snark
        let agg_k = 12;
        let agg_lookup_bits = agg_k - 1;
        let agg_params = gen_srs(agg_k as u32);
        let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
            &agg_params,
            vec![dummy_snark],
            VerifierUniversality::Full
        );

        println!("Aggregation circuit calculating params");
        let agg_config = agg_circuit.calculate_params(Some(10));

        // let start0 = start_timer!(|| "gen vk & pk");
        println!("Aggregation circuit generating pk");
        let pk = gen_pk(&agg_params, &agg_circuit, None);
        
        let break_points = agg_circuit.break_points();

        // std::fs::remove_file(Path::new("examples/agg.pk")).ok();
        // let _pk = gen_pk(&params, &agg_circuit, Some(Path::new("examples/agg.pk")));
        // end_timer!(start0);
        // let pk = read_pk::<AggregationCircuit>(Path::new("examples/agg.pk"), agg_config).unwrap();
        // std::fs::remove_file(Path::new("examples/agg.pk")).ok();
        // let break_points = agg_circuit.break_points();

        println!("Generating snark");
        let snark = generate_circuit();
        
        let agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            agg_config,
            &agg_params,
            vec![snark],
            VerifierUniversality::Full,
        ).use_break_points(break_points.clone());

        println!("Generating aggregation snark");
        let agg_snark = gen_snark_shplonk(&agg_params, &pk, agg_circuit, None::<&str>);
        println!("Aggregation snark success");

    }
}



// Note: Apparently MSMs are for generating KZG params rather than proofs.
// When I am configuring a circuit with BaseBuilder do I also need to pass in the number of columns?
// I do apparently, because if you look into BaseCircuitBuilder.synthesize() they populate the basic_gates
// array only when the number of advice columns > 0.