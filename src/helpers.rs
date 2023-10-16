use halo2_base::{
    AssignedValue,
    halo2_proofs::halo2curves::{bn256::Fr, ff::PrimeField},
    gates::{
        circuit::builder::BaseCircuitBuilder,
        GateInstructions
    },
    QuantumCell::{Existing, Constant},
    utils::fs::gen_srs
};
use halo2_rsa::{
    BigUintConfig, BigUintInstructions, RSAInstructions, RSAConfig, RSAPubE, RSAPublicKey, RSASignature,
};
use halo2_sha256_unoptimized::Sha256Chip;
use snark_verifier_sdk::{
    gen_pk,
    halo2::gen_snark_shplonk,
    Snark,
};
use crate::sha256_bit_circuit::Sha256BitCircuit;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::vec;
use x509_parser::pem::parse_x509_pem;
use x509_parser::public_key::PublicKey;
use num_bigint::BigUint;
use itertools::Itertools;
use openssl::ssl::{SslConnector, SslMethod};
use std::net::TcpStream;
use std::io::Write;

pub fn download_tls_certs_from_domain(
    domain: &str,
    certs_path: &str
) {
    let port = "443";

    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    let stream = TcpStream::connect(format!("{}:{}", domain, port)).unwrap();
    let ssl_stream = connector.connect(domain, stream).unwrap();

    // Obtain the certificate chain
    let cert_chain = ssl_stream.ssl().verified_chain().unwrap();

    // Convert each certificate in the chain to PEM format and save to a file
    for (i, certificate) in cert_chain.iter().enumerate() {
        let pem = certificate.to_pem().unwrap();
        let filename = format!("{}_{}.pem", certs_path, 3 - i);
        let mut file = File::create(&filename).unwrap();
        file.write_all(&pem).unwrap();
        println!("Saved certificate to {}", filename);
    }
}

pub fn extract_public_key(issuer_cert_path: &str) -> BigUint {
    let mut issuer_cert_file = File::open(issuer_cert_path).expect("Failed to open cert 2PEM file");
    let mut issuer_cert_pem_buffer = Vec::new();
    issuer_cert_file.read_to_end(&mut issuer_cert_pem_buffer).expect("Failed to read cert 2 PEM file");

    // Parse the PEM certificate using x509-parser
    let issuer_cert_pem = parse_x509_pem(&issuer_cert_pem_buffer).expect("Failed to parse cert 3 PEM").1;
    let issuer_cert = issuer_cert_pem.parse_x509().expect("Failed to parse PEM certificate");
    
    // Extract the public key
    match issuer_cert.public_key().parsed().unwrap() {
        PublicKey::RSA(pub_key) => {
            BigUint::from_bytes_be(pub_key.modulus)
        },
        _ => panic!("Failed to grab modulus. Not RSA")
    }
}

pub fn extract_tbs_and_sig(verify_cert_path: &str) -> (Vec<u8>, BigUint) {
    // Read the PEM certificate from a file
    let mut cert_file = File::open(verify_cert_path).expect("Failed to open PEM file");
    let mut cert_pem_buffer = Vec::new();
    cert_file.read_to_end(&mut cert_pem_buffer).expect("Failed to read PEM file");

    // Parse the PEM certificate using x509-parser
    let cert_pem = parse_x509_pem(&cert_pem_buffer).expect("Failed to parse cert 3 PEM").1;
    let cert = cert_pem.parse_x509().expect("Failed to parse PEM certificate");

    // Extract the TBS (To-Be-Signed) data from the certificate
    let tbs = cert.tbs_certificate.as_ref();
    // println!("TBS (To-Be-Signed): {:x?}", tbs);

    // Extract the signature from cert 3
    let signature_bytes = &cert.signature_value;
    let signature_bigint = BigUint::from_bytes_be(&signature_bytes.data);
    // println!("Signature: {:?}", signature_bigint);

    (tbs.to_vec(), signature_bigint)
}

pub fn create_default_rsa_circuit_with_instances(
    k: usize,
    tbs: Vec<u8>,
    public_key_modulus: BigUint,
    signature_bigint: BigUint
) -> BaseCircuitBuilder<Fr> {
    // Circuit inputs
    let limb_bits = 64;
    let default_bits = 2048;
    let exp_bits = 5; // UNUSED
    let default_e = 65537_u32;

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
    println!("Hashed TBS: {:?}", hashed_tbs);
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
    builder.use_params(circuit_params)
}

pub fn create_default_unoptimized_sha256_circuit_with_instances(
    k: usize,
    tbs: Vec<u8>
) -> BaseCircuitBuilder<Fr> {
    // Circuit inputs
    let max_byte_sizes = vec![1280]; // Use precomputed SHA

    let mut builder = BaseCircuitBuilder::new(false);
    // Set rows
    builder.set_k(k);
    builder.set_lookup_bits(k - 1);
    builder.set_instance_columns(1);

    let range = builder.range_chip();
    let ctx = builder.main(0);

    let mut sha256_chip = Sha256Chip::construct(max_byte_sizes, range.clone(), true);
    let result = sha256_chip.digest(ctx, &tbs, Some(0)).unwrap();

    // Insert output hash as public instance for circuit
    builder.assigned_instances[0].extend(result.output_bytes);

    let circuit_params = builder.calculate_params(Some(10));
    println!("Circuit params: {:?}", circuit_params);
    builder.use_params(circuit_params)
}

pub fn generate_rsa_circuit_with_instances(verify_cert_path: &str, issuer_cert_path: &str, k: usize) -> Snark {
    let (tbs, signature_bigint) = extract_tbs_and_sig(verify_cert_path);

    let public_key_modulus = extract_public_key(issuer_cert_path);

    let builder = create_default_rsa_circuit_with_instances(k, tbs, public_key_modulus, signature_bigint);

    // Generate params
    println!("Generate params");
    let params = gen_srs(k as u32);
    
    // println!("Generating proving key");
    let pk = gen_pk(&params, &builder, None);

    // Generate proof
    println!("Generating proof");
    gen_snark_shplonk(&params, &pk, builder, None::<&str>)
}

pub fn generate_unoptimized_sha256_circuit_with_instances(verify_cert_path: &str, k: usize) -> Snark {
    let (tbs, _) = extract_tbs_and_sig(verify_cert_path);

    let builder = create_default_unoptimized_sha256_circuit_with_instances(k, tbs);

    // Generate params
    println!("Generate params");
    let params = gen_srs(k as u32);

    // println!("Generating proving key");
    let pk = gen_pk(&params, &builder, None);

    // Generate proof
    println!("Generating proof");
    gen_snark_shplonk(&params, &pk, builder, None::<&str>)
}

pub fn generate_zkevm_sha256_circuit(verify_cert_path: &str, k: usize) -> Snark {
    let (tbs, _) = extract_tbs_and_sig(verify_cert_path);

    // Generate params
    println!("Generate params");
    let params = gen_srs(k as u32);
    
    // println!("Generating proving key");
    let dummy_circuit = Sha256BitCircuit::new(
        Some(2usize.pow(k as u32) - 109),
        vec![tbs.to_vec()],
        false
    );
    let pk = gen_pk(&params, &dummy_circuit, None);
    println!("pk stats: {:?} {:?} {:?} {:?}", pk.get_vk().cs().num_selectors(), pk.get_vk().cs().num_advice_columns(), pk.get_vk().cs().num_fixed_columns(), pk.get_vk().cs().num_instance_columns());
    // Generate proof
    println!("Generating proof");
    let mut sha256_bit_circuit = Sha256BitCircuit::new(
        Some(2usize.pow(k as u32) - 109),
        vec![tbs.to_vec()],
        true
    );
    sha256_bit_circuit.set_instances(vec![
        Fr::from_u128(0x00000000000000000000000000000000eeb16b6a466d78243f0210594c79e2ea),
        Fr::from_u128(0x000000000000000000000000000000005773a131a99b9c98158c743ebd7e521a)]);
    gen_snark_shplonk(&params, &pk, sha256_bit_circuit, None::<&str>)
}
