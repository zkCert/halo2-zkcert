use crate::X509VerifierAggregationCircuit;
use super::sha256_bit_circuit::Sha256BitCircuit;
use std::path::Path;

use halo2_base::{
    AssignedValue,
    halo2_proofs::halo2curves::bn256::Fr,
    gates::{
        circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
        GateInstructions
    },
    QuantumCell::{Existing, Constant},
    utils::fs::gen_srs
};
use halo2_rsa::{
    BigUintConfig, BigUintInstructions, RSAInstructions, RSAConfig, RSAPubE, RSAPublicKey, RSASignature,
};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::{AggregationConfigParams, VerifierUniversality, AggregationCircuit}, gen_snark_shplonk},
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
    Snark,
    CircuitExt
};

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::vec;
use x509_parser::pem::parse_x509_pem;
use x509_parser::public_key::PublicKey;
use num_bigint::BigUint;
use itertools::Itertools;

fn generate_rsa_circuit_with_instances(verify_cert_path: &str, issuer_cert_path: &str, k: usize) -> Snark {
    // Read the PEM certificate from a file
    let mut cert_file = File::open(verify_cert_path).expect("Failed to open PEM file");
    let mut cert_pem_buffer = Vec::new();
    cert_file.read_to_end(&mut cert_pem_buffer).expect("Failed to read PEM file");

    // Parse the PEM certificate using x509-parser
    let cert_pem = parse_x509_pem(&cert_pem_buffer).expect("Failed to parse cert 3 PEM").1;
    let cert = cert_pem.parse_x509().expect("Failed to parse PEM certificate");

    // Extract the TBS (To-Be-Signed) data from the certificate 3
    let tbs = cert.tbs_certificate.as_ref();
    // println!("TBS (To-Be-Signed): {:x?}", tbs);

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
    let limb_bits = 64;
    let default_bits = 2048;
    let exp_bits = 5;
    let default_e = 65537 as u32;

    let mut builder = BaseCircuitBuilder::new(false);
    // Set rows
    builder.set_k(k);
    builder.set_lookup_bits(k - 1);
    builder.set_instance_columns(1);

    let range = builder.range_chip();
    let ctx = builder.main(0);

    let bigint_chip = BigUintConfig::construct(range.clone(), limb_bits);
    let rsa_chip = RSAConfig::construct(bigint_chip.clone(), default_bits, exp_bits);

    // Hash in pure Rust vs in-circuit
    let hashed_tbs = Sha256::digest(tbs);
    let mut hashed_bytes: Vec<AssignedValue<Fr>> = hashed_tbs.iter().map(|limb| ctx.load_witness(Fr::from(*limb as u64))).collect_vec();
    hashed_bytes.reverse();
    let bytes_bits = hashed_bytes.len() * 8;
    let limb_bits = bigint_chip.limb_bits();
    let limb_bytes = limb_bits / 8;
    let mut hashed_u64s = vec![];
    let bases = (0..limb_bytes)
        .map(|i| Fr::from(1u64 << (8 * i)))
        .map(Constant)
        .collect_vec();
    for i in 0..(bytes_bits / limb_bits) {
        let left = hashed_bytes[limb_bytes * i..limb_bytes * (i + 1)]
            .iter()
            .map(|x| Existing(*x))
            .collect_vec();
        let sum = bigint_chip.gate().inner_product(ctx, left, bases.clone());
        hashed_u64s.push(sum);
    }

    // Generate values to be fed into the circuit (Pure Rust)
    // Verify Cert
    let e_fix = RSAPubE::Fix(BigUint::from(default_e));
    let public_key = RSAPublicKey::new(public_key_modulus.clone(), e_fix);     // cloning might be slow
    let public_key = rsa_chip.assign_public_key(ctx, public_key).unwrap();

    let signature = RSASignature::new(signature_bigint.clone());             // cloning might be slow
    let signature = rsa_chip.assign_signature(ctx, signature).unwrap();

    let is_valid = rsa_chip.verify_pkcs1v15_signature(ctx, &public_key, &hashed_u64s, &signature).unwrap();
    rsa_chip.biguint_config()
        .gate()
        .assert_is_const(ctx, &is_valid, &Fr::one());
    
    // Insert input hash as public instance for circuit
    hashed_bytes.reverse();
    builder.assigned_instances[0].extend(hashed_bytes);

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

fn generate_zkevm_sha256_circuit_with_instance(verify_cert_path: &str, issuer_cert_path: &str, k: usize) -> Snark {
    // Read the PEM certificate from a file
    let mut cert_file = File::open(verify_cert_path).expect("Failed to open PEM file");
    let mut cert_pem_buffer = Vec::new();
    cert_file.read_to_end(&mut cert_pem_buffer).expect("Failed to read PEM file");

    // Parse the PEM certificate using x509-parser
    let cert_pem = parse_x509_pem(&cert_pem_buffer).expect("Failed to parse cert 3 PEM").1;
    let cert = cert_pem.parse_x509().expect("Failed to parse PEM certificate");

    // Extract the TBS (To-Be-Signed) data from the certificate 3
    let tbs = cert.tbs_certificate.as_ref();
    println!("TBS (To-Be-Signed) Length: {:x?}", tbs.len().to_string());

    let mut issuer_cert_file = File::open(issuer_cert_path).expect("Failed to open cert 2PEM file");
    let mut issuer_cert_pem_buffer = Vec::new();
    issuer_cert_file.read_to_end(&mut issuer_cert_pem_buffer).expect("Failed to read cert 2 PEM file");

    // Generate params
    println!("Generate params");
    let params = gen_srs(k as u32);
    
    // println!("Generating proving key");
    let dummy_circuit = Sha256BitCircuit::new(Some(2usize.pow(k as u32) - 109), vec![], false);
    let pk = gen_pk(&params, &dummy_circuit, None);
    
    // Generate proof
    println!("Generating proof");
    let sha256_bit_circuit = Sha256BitCircuit::new(Some(2usize.pow(k as u32) - 109), vec![tbs.to_vec()], true);
    gen_snark_shplonk(&params, &pk, sha256_bit_circuit, None::<&str>)
}

#[test]
fn test_x509_verifier_aggregation_circuit_evm_verification1() {
    println!("Generating dummy snark");
    let snark1 = generate_zkevm_sha256_circuit_with_instance(
        "./certs/cert_3.pem",
        "./certs/cert_2.pem",
        11
    );
    let snark2 = generate_rsa_circuit_with_instances(
        "./certs/cert_3.pem",
        "./certs/cert_2.pem",
        17
    );
    let snark3 = generate_zkevm_sha256_circuit_with_instance(
        "./certs/cert_2.pem",
        "./certs/cert_1.pem",
        11
    );
    let snark4 = generate_rsa_circuit_with_instances(
        "./certs/cert_2.pem",
        "./certs/cert_1.pem",
        17
    );

    // Create custom aggregation circuit using the snark that verifiers input of signature algorithm is same as output of hash function
    let agg_k = 23;
    let agg_lookup_bits = agg_k - 1;
    let agg_params = gen_srs(agg_k as u32);
    let mut agg_circuit = X509VerifierAggregationCircuit::new(
        CircuitBuilderStage::Keygen,
        AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
        &agg_params,
        vec![snark1.clone(), snark2.clone(), snark3.clone(), snark4.clone()],
        VerifierUniversality::Full
    ).aggregation_circuit;

    println!("Aggregation circuit calculating params");
    let agg_config = agg_circuit.calculate_params(Some(10));

    // let start0 = start_timer!(|| "gen vk & pk");
    println!("Aggregation circuit generating pk");
    let pk = gen_pk(&agg_params, &agg_circuit, None);
    
    let break_points = agg_circuit.break_points();

    let agg_circuit = X509VerifierAggregationCircuit::new(
        CircuitBuilderStage::Prover,
        agg_config,
        &agg_params,
        vec![snark1, snark2, snark3, snark4],
        VerifierUniversality::Full,
    ).aggregation_circuit.use_break_points(break_points.clone());

    println!("Generating aggregation snark");
    let _agg_snark = gen_snark_shplonk(&agg_params, &pk, agg_circuit.clone(), None::<&str>);
    println!("Aggregation snark success");

    println!("Generate EVM verifier");
    let num_instances = agg_circuit.num_instance();
    let instances = agg_circuit.instances();
    let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
        &agg_params,
        pk.get_vk(),
        num_instances,
        Some(Path::new("AggregationVerifierFinal.sol")),
    );
    
    println!("Generating evm aggregation proof");
    let proof = gen_evm_proof_shplonk(&agg_params, &pk, agg_circuit, instances.clone());

    println!("Size of the contract: {} bytes", deployment_code.len());

    println!("Verifying EVM proof");
    evm_verify(deployment_code, instances, proof);

}

