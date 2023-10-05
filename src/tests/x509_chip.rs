use crate::{X509CertificateVerifierChip, SignatureAlgorithm, HashFunction};
use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, gates::GateInstructions};
use halo2_rsa::{
    BigUintConfig, BigUintInstructions, RSAConfig, RSAInstructions, RSAPubE, RSAPublicKey, RSASignature,
};
use halo2_sha256_unoptimized::Sha256Chip;
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

use num_bigint::BigUint;

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

        // Verify Cert in Rust
        let _is_valid = check_signature(&cert, &issuer_cert);

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
fn test_verify_pkcs1_sha256_with_rsa2() {
    impl_verify_pkcs1_sha256_with_rsa_test_circuit!(
        "./certs/cert_3.pem",
        "./certs/cert_2.pem",
        false
    );
}

#[test]
fn test_verify_pkcs1_sha256_with_rsa3() {
    impl_verify_pkcs1_sha256_with_rsa_test_circuit!(
        "./certs/cert_2.pem",
        "./certs/cert_1.pem",
        false
    );
}

#[test]
fn test_verify_pkcs1_sha256_with_rsa4() {
    impl_verify_pkcs1_sha256_with_rsa_test_circuit!(
        "./certs/cert_3.pem",
        "./certs/cert_1.pem",
        true
    );
}