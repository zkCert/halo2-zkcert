use crate::{X509CertificateVerifierChip, SignatureAlgorithm, HashFunction};

use halo2_base::{
    halo2_proofs::halo2curves::bn256::Fr,
    gates::{
        circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
        GateInstructions, RangeInstructions
    },
    utils::fs::gen_srs
};
use halo2_rsa::{
    BigUintConfig, BigUintInstructions, RSAConfig, RSAInstructions, RSAPubE, RSAPublicKey, RSASignature,
};
use halo2_sha256_unoptimized::Sha256Chip;
use snark_verifier_sdk::{
    SHPLONK,
    gen_pk,
    halo2::{aggregation::{AggregationConfigParams, VerifierUniversality, AggregationCircuit}, gen_snark_shplonk},
    Snark,
};

use rand::{thread_rng, Rng};
use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::vec;
use x509_parser::pem::parse_x509_pem;
use x509_parser::public_key::PublicKey;

use num_bigint::BigUint;

fn generate_sha256_with_rsa_circuit(verify_cert_path: &str, issuer_cert_path: &str) -> Snark {
    // Read the PEM certificate from a file
    let mut cert_file = File::open(verify_cert_path).expect("Failed to open PEM file");
    let mut cert_pem_buffer = Vec::new();
    cert_file.read_to_end(&mut cert_pem_buffer).expect("Failed to read PEM file");

    // Parse the PEM certificate using x509-parser
    let cert_pem = parse_x509_pem(&cert_pem_buffer).expect("Failed to parse cert 3 PEM").1;
    let cert = cert_pem.parse_x509().expect("Failed to parse PEM certificate");

    // Extract the TBS (To-Be-Signed) data from the certificate 3
    let tbs = &cert.tbs_certificate.as_ref();

    // Extract the signature from cert 3
    let signature_bytes = &cert.signature_value;
    let signature_bigint = BigUint::from_bytes_be(&signature_bytes.data);
    // println!("Signature: {:?}", signature_bigint);

    let mut issuer_cert_file = File::open(issuer_cert_path).expect("Failed to open cert 2PEM file");
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

    // Circuit inputs
    let k: usize = 18;
    let limb_bits = 64;
    let default_bits = 2048;
    let exp_bits = 5;
    let default_e = 65537 as u32;
    let max_byte_sizes = vec![1280];

    let mut builder = BaseCircuitBuilder::new(false);
    // Set rows
    builder.set_k(k);
    builder.set_lookup_bits(k - 1);
    builder.set_instance_columns(1);

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
    // Verify Cert
    let e_fix = RSAPubE::Fix(BigUint::from(default_e));
    let public_key = RSAPublicKey::new(public_key_modulus.clone(), e_fix);     // cloning might be slow
    let public_key = rsa_chip.assign_public_key(ctx, public_key).unwrap();

    let signature = RSASignature::new(signature_bigint.clone());             // cloning might be slow
    let signature = rsa_chip.assign_signature(ctx, signature).unwrap();

    let (is_valid, _hashed_msg) =
        chip.verify_pkcs1_sha256_with_rsa(ctx, &public_key, &tbs, &signature).unwrap();
    rsa_chip.biguint_config()
        .gate()
        .assert_is_const(ctx, &is_valid, &Fr::one());

    // let x = ctx.load_witness(Fr::from(14));
    // range.gate().add(ctx, x, x);

    let circuit_params = builder.calculate_params(Some(10));
    println!("Circuit params: {:?}", circuit_params);
    let builder = builder.use_params(circuit_params);

    // Generate params
    println!("Generate params");
    let params = gen_srs(k as u32);
    
    // println!("Generating proving key");
    let pk = gen_pk(&params, &builder, None);

    // Generate proof
    println!("Generating proof");
    gen_snark_shplonk(&params, &pk, builder, None::<&str>)
}

#[test]
fn test_aggregation_sha256_with_rsa1() {
    
    fn generate_circuit() -> Snark {
        let k: usize = 18;
        let lookup_bits = k as usize - 1;

        // Circuit inputs
        let limb_bits = 64;
        let default_bits = 512;
        let exp_bits = 5;
        let default_e = 65537 as u32;
        let max_byte_sizes = vec![192];

        let mut builder = BaseCircuitBuilder::new(false);
        // Set rows
        builder.set_k(k);
        builder.set_lookup_bits(lookup_bits);
        builder.set_instance_columns(1);

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
        
        let (is_valid, _hashed_msg) =
            chip.verify_pkcs1_sha256_with_rsa(ctx, &public_key, &msg, &sign).unwrap();
        
        range.gate().assert_is_const(ctx, &is_valid, &Fr::one());

        // let x = ctx.load_witness(Fr::from(14));
        // range.gate().add(ctx, x, x);

        let circuit_params = builder.calculate_params(Some(10));
        println!("Circuit params: {:?}", circuit_params);
        let builder = builder.use_params(circuit_params);

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
    let snark1 = generate_circuit();
    let snark2 = generate_circuit();

    // Create an aggregation circuit using the snark
    let agg_k = 12;
    let agg_lookup_bits = agg_k - 1;
    let agg_params = gen_srs(agg_k as u32);
    let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
        &agg_params,
        vec![snark1.clone(), snark2.clone()],
        VerifierUniversality::Full
    );

    println!("Aggregation circuit calculating params");
    let agg_config = agg_circuit.calculate_params(Some(10));
    println!("Aggregation circuit params: {:?}", agg_config);

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

    let agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Prover,
        agg_config,
        &agg_params,
        vec![snark1, snark2],
        VerifierUniversality::Full,
    ).use_break_points(break_points.clone());

    println!("Generating aggregation snark");
    let _agg_snark = gen_snark_shplonk(&agg_params, &pk, agg_circuit, None::<&str>);
    println!("Aggregation snark success");

}

#[test]
fn test_aggregation_sha256_with_rsa2() {
    println!("Generating dummy snark");
    let snark1 = generate_sha256_with_rsa_circuit(
        "./certs/cert_3.pem",
        "./certs/cert_2.pem",
    );
    let snark2 = generate_sha256_with_rsa_circuit(
        "./certs/cert_2.pem",
        "./certs/cert_1.pem",
    );

    // Create an aggregation circuit using the snark
    let agg_k = 16;
    let agg_lookup_bits = agg_k - 1;
    let agg_params = gen_srs(agg_k as u32);
    let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
        &agg_params,
        vec![snark1.clone(), snark2.clone()],
        VerifierUniversality::Full
    );

    println!("Aggregation circuit calculating params");
    let agg_config = agg_circuit.calculate_params(Some(10));
    println!("Aggregation circuit params: {:?}", agg_config);

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

    let agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Prover,
        agg_config,
        &agg_params,
        vec![snark1, snark2],
        VerifierUniversality::Full,
    ).use_break_points(break_points.clone());

    println!("Generating aggregation snark");
    let _agg_snark = gen_snark_shplonk(&agg_params, &pk, agg_circuit, None::<&str>);
    println!("Aggregation snark success");

}