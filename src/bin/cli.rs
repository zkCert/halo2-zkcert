use clap::{Parser, Subcommand};
use halo2_zkcert::helpers::*;
use halo2_zkcert::*;
use crate::sha256_bit_circuit::Sha256BitCircuit;
use std::env;
use halo2_base::{
    halo2_proofs::halo2curves::bn256::Fr,
    halo2_proofs::plonk::Circuit,
    gates::circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage, BaseCircuitParams},
    utils::fs::gen_srs
};
use snark_verifier_sdk::{
    read_pk,
    gen_pk,
    halo2::{aggregation::{AggregationConfigParams, VerifierUniversality, AggregationCircuit}, gen_snark_shplonk, read_snark},
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
    CircuitExt
};
use std::path::Path;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand, Clone)]
enum Commands {
    /// Generate a setup parameter (not for production).
    GenParams {
        /// k parameter for circuit.
        #[arg(long)]
        k: u32,
        #[arg(short, long, default_value = "./params")]
        params_path: String,
    },
    /// Generate proving keys for RSA circuit
    GenRsaKeys {
        /// k parameter for circuit.
        #[arg(long, default_value = "17")]
        k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./params")]
        params_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/rsa_1.pk")]
        pk_path: String,
        #[arg(long, default_value = "./certs/cert_3.pem")]
        verify_cert_path: String,
        #[arg(long, default_value = "./certs/cert_2.pem")]
        issuer_cert_path: String
    },
    /// Generate proving keys for unoptimized SHA256 circuit
    GenUnoptimizedSha256Keys {
        /// k parameter for circuit.
        #[arg(long, default_value = "19")]
        k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./params")]
        params_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/unoptimized_sha256_1.pk")]
        pk_path: String,
        #[arg(long, default_value = "./certs/cert_3.pem")]
        verify_cert_path: String,
    },
    /// Generate proving keys for ZKEVM fast SHA256 circuit
    GenZkevmSha256Keys {
        /// k parameter for circuit.
        #[arg(long, default_value = "11")]
        k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./params")]
        params_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/zkevm_sha256_1.pk")]
        pk_path: String,
        #[arg(long, default_value = "./certs/cert_3.pem")]
        verify_cert_path: String,
    },
    ProveRsa {
        /// k parameter for circuit.
        #[arg(long, default_value = "17")]
        k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./params")]
        params_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/rsa_1.pk")]
        pk_path: String,
        #[arg(long, default_value = "./certs/cert_3.pem")]
        verify_cert_path: String,
        #[arg(long, default_value = "./certs/cert_2.pem")]
        issuer_cert_path: String,
        /// output proof file
        #[arg(long, default_value = "./build/rsa_1.proof")]
        proof_path: String,
    },
    ProveUnoptimizedSha256 {
        /// k parameter for circuit.
        #[arg(long, default_value = "19")]
        k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./params")]
        params_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/unoptimized_sha256_1.pk")]
        pk_path: String,
        #[arg(long, default_value = "./certs/cert_3.pem")]
        verify_cert_path: String,
        #[arg(long, default_value = "./build/unoptimized_sha256_1.proof")]
        proof_path: String,
    },
    ProveZkevmSha256 {
        /// k parameter for circuit.
        #[arg(long, default_value = "11")]
        k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./params")]
        params_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/zkevm_sha256_1.pk")]
        pk_path: String,
        #[arg(long, default_value = "./certs/cert_3.pem")]
        verify_cert_path: String,
        #[arg(long, default_value = "./build/zkevm_sha256_1.proof")]
        proof_path: String,
    },
    /// Generate proving keys for x509 aggregation circuit
    GenX509AggKeys {
        /// k parameter for circuit.
        #[arg(long, default_value = "22")]
        agg_k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./params")]
        params_path: String,
        #[arg(short, long, default_value = "./build/rsa_1.proof")]
        rsa_1_proof_path: String,
        #[arg(short, long, default_value = "./build/unoptimized_sha256_1.proof")]
        unoptimized_sha256_1_proof_path: String,
        #[arg(short, long, default_value = "./build/rsa_2.proof")]
        rsa_2_proof_path: String,
        #[arg(short, long, default_value = "./build/unoptimized_sha256_2.proof")]
        unoptimized_sha256_2_proof_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/x509_agg.pk")]
        pk_path: String,
    },
    /// Generate proof for x509 aggregation circuit
    GenX509AggProof {
        /// k parameter for circuit.
        #[arg(long, default_value = "22")]
        agg_k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./params")]
        params_path: String,
        #[arg(short, long, default_value = "./build/rsa_1.proof")]
        rsa_1_proof_path: String,
        #[arg(short, long, default_value = "./build/unoptimized_sha256_1.proof")]
        unoptimized_sha256_1_proof_path: String,
        #[arg(short, long, default_value = "./build/rsa_2.proof")]
        rsa_2_proof_path: String,
        #[arg(short, long, default_value = "./build/unoptimized_sha256_2.proof")]
        unoptimized_sha256_2_proof_path: String,
        #[arg(long, default_value = "./build/x509_agg.pk")]
        pk_path: String,
        #[arg(long, default_value = "./build/x509_agg.proof")]
        agg_proof_path: String,
    },
    /// Generate EVM proof and verification for x509 aggregation circuit
    GenX509AggEVMProof {
        /// k parameter for circuit.
        #[arg(long, default_value = "22")]
        agg_k: u32,
        /// setup parameters path
        #[arg(short, long, default_value = "./params")]
        params_path: String,
        #[arg(short, long, default_value = "./build/rsa_1.proof")]
        rsa_1_proof_path: String,
        #[arg(short, long, default_value = "./build/unoptimized_sha256_1.proof")]
        unoptimized_sha256_1_proof_path: String,
        #[arg(short, long, default_value = "./build/rsa_2.proof")]
        rsa_2_proof_path: String,
        #[arg(short, long, default_value = "./build/unoptimized_sha256_2.proof")]
        unoptimized_sha256_2_proof_path: String,
        /// proving key path
        #[arg(long, default_value = "./build/x509_agg.pk")]
        pk_path: String,
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenParams { k, params_path } => {
            env::set_var("PARAMS_DIR", params_path);
            gen_srs(k);
        },
        Commands::GenRsaKeys {
            k,
            params_path,
            pk_path,
            verify_cert_path,
            issuer_cert_path,
        } => {
            env::set_var("PARAMS_DIR", params_path);
            let params = gen_srs(k);

            let (tbs, signature_bigint) = extract_tbs_and_sig(&verify_cert_path);
            let public_key_modulus = extract_public_key(&issuer_cert_path);

            let builder = create_default_rsa_circuit_with_instances(k as usize, tbs, public_key_modulus, signature_bigint);

            gen_pk(&params, &builder, Some(Path::new(&pk_path)));
        },
        Commands::GenUnoptimizedSha256Keys {
            k,
            params_path,
            pk_path,
            verify_cert_path,
        } => {
            env::set_var("PARAMS_DIR", params_path);
            let params = gen_srs(k);

            let (tbs, _) = extract_tbs_and_sig(&verify_cert_path);

            let builder = create_default_unoptimized_sha256_circuit_with_instances(k as usize, tbs);

            gen_pk(&params, &builder, Some(Path::new(&pk_path)));
        },
        Commands::GenZkevmSha256Keys {
            k,
            params_path,
            pk_path,
            verify_cert_path,
        } => {
            env::set_var("PARAMS_DIR", params_path);
            let params = gen_srs(k);

            let (tbs, _) = extract_tbs_and_sig(&verify_cert_path);

            let dummy_circuit = Sha256BitCircuit::new(
                CircuitBuilderStage::Keygen,
                BaseCircuitParams {k: k as usize, num_fixed: 1, num_advice_per_phase: vec![1, 0, 0], num_lookup_advice_per_phase: vec![0, 0, 0], lookup_bits: Some(0), num_instance_columns: 1},
                Some(2usize.pow(k) - 109),
                vec![tbs.to_vec()],
                false
            );

            gen_pk(&params, &dummy_circuit, Some(Path::new(&pk_path)));
        },
        Commands::ProveRsa {
            k,
            params_path,
            pk_path,
            verify_cert_path,
            issuer_cert_path,
            proof_path,
        } => {
            env::set_var("PARAMS_DIR", params_path);
            let params = gen_srs(k);

            let (tbs, signature_bigint) = extract_tbs_and_sig(&verify_cert_path);
            let public_key_modulus = extract_public_key(&issuer_cert_path);
            
            let builder = create_default_rsa_circuit_with_instances(k as usize, tbs, public_key_modulus, signature_bigint);
            let pk = read_pk::<BaseCircuitBuilder<Fr>>(Path::new(&pk_path), builder.params()).unwrap();

            gen_snark_shplonk(&params, &pk, builder, Some(Path::new(&proof_path)));
        },
        Commands::ProveUnoptimizedSha256 {
            k,
            params_path,
            pk_path,
            verify_cert_path,
            proof_path,
        } => {
            env::set_var("PARAMS_DIR", params_path);
            let params = gen_srs(k);

            let (tbs, _) = extract_tbs_and_sig(&verify_cert_path);
            
            let builder = create_default_unoptimized_sha256_circuit_with_instances(k as usize, tbs);
            let pk = read_pk::<BaseCircuitBuilder<Fr>>(Path::new(&pk_path), builder.params()).unwrap();

            gen_snark_shplonk(&params, &pk, builder, Some(Path::new(&proof_path)));
        },
        Commands::ProveZkevmSha256 {
            k,
            params_path,
            pk_path,
            verify_cert_path,
            proof_path,
        } => {
            env::set_var("PARAMS_DIR", params_path);
            let params = gen_srs(k);

            let (tbs, _) = extract_tbs_and_sig(&verify_cert_path);
            let base_circuit_params = BaseCircuitParams {k: k as usize, num_fixed: 1, num_advice_per_phase: vec![1, 0, 0], num_lookup_advice_per_phase: vec![0, 0, 0], lookup_bits: Some(0), num_instance_columns: 1};
            let sha256_bit_circuit = Sha256BitCircuit::new(
                CircuitBuilderStage::Prover,
                base_circuit_params.clone(),
                Some(2usize.pow(k) - 109),
                vec![tbs.to_vec()],
                true
            );
            let pk = read_pk::<BaseCircuitBuilder<Fr>>(Path::new(&pk_path), base_circuit_params).unwrap();

            gen_snark_shplonk(&params, &pk, sha256_bit_circuit, Some(Path::new(&proof_path)));
        },
        Commands::GenX509AggKeys {
            agg_k,
            params_path,
            rsa_1_proof_path,
            unoptimized_sha256_1_proof_path,
            rsa_2_proof_path,
            unoptimized_sha256_2_proof_path,
            pk_path,
        } => {
            env::set_var("PARAMS_DIR", params_path);
            let agg_lookup_bits = agg_k - 1;
            let agg_params = gen_srs(agg_k);

            let snarks = vec![
                read_snark(Path::new(&rsa_1_proof_path)).unwrap(),
                read_snark(Path::new(&unoptimized_sha256_1_proof_path)).unwrap(),
                read_snark(Path::new(&rsa_2_proof_path)).unwrap(),
                read_snark(Path::new(&unoptimized_sha256_2_proof_path)).unwrap(),
            ];

            let mut agg_circuit = X509VerifierAggregationCircuit::new(
                CircuitBuilderStage::Keygen,
                AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
                &agg_params,
                snarks,
                VerifierUniversality::Full
            );

            agg_circuit.calculate_params(Some(10));

            gen_pk(&agg_params, &agg_circuit, Some(Path::new(&pk_path)));
        },
        Commands::GenX509AggProof {
            agg_k,
            params_path,
            rsa_1_proof_path,
            unoptimized_sha256_1_proof_path,
            rsa_2_proof_path,
            unoptimized_sha256_2_proof_path,
            pk_path,
            agg_proof_path,
        } => {
            env::set_var("PARAMS_DIR", params_path);
            let agg_lookup_bits = agg_k - 1;
            let agg_params = gen_srs(agg_k);

            let snarks = vec![
                read_snark(Path::new(&rsa_1_proof_path)).unwrap(),
                read_snark(Path::new(&unoptimized_sha256_1_proof_path)).unwrap(),
                read_snark(Path::new(&rsa_2_proof_path)).unwrap(),
                read_snark(Path::new(&unoptimized_sha256_2_proof_path)).unwrap(),
            ];

            let mut agg_circuit = X509VerifierAggregationCircuit::new(
                CircuitBuilderStage::Keygen,
                AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
                &agg_params,
                snarks.clone(),
                VerifierUniversality::Full
            );

            let agg_config = agg_circuit.calculate_params(Some(10));
            let break_points = vec![];
            
            let agg_circuit = X509VerifierAggregationCircuit::new(
                CircuitBuilderStage::Prover,
                agg_config,
                &agg_params,
                snarks,
                VerifierUniversality::Full,
            ).use_break_points(break_points.clone());

            let pk = read_pk::<AggregationCircuit>(Path::new(&pk_path), agg_circuit.params()).unwrap();
            gen_snark_shplonk(&agg_params, &pk, agg_circuit.clone(), Some(Path::new(&agg_proof_path)));
        },
        Commands::GenX509AggEVMProof {
            agg_k,
            params_path,
            rsa_1_proof_path,
            unoptimized_sha256_1_proof_path,
            rsa_2_proof_path,
            unoptimized_sha256_2_proof_path,
            pk_path,
        } => {
            env::set_var("PARAMS_DIR", params_path);
            let agg_lookup_bits = agg_k - 1;
            let agg_params = gen_srs(agg_k);

            let snarks = vec![
                read_snark(Path::new(&rsa_1_proof_path)).unwrap(),
                read_snark(Path::new(&unoptimized_sha256_1_proof_path)).unwrap(),
                read_snark(Path::new(&rsa_2_proof_path)).unwrap(),
                read_snark(Path::new(&unoptimized_sha256_2_proof_path)).unwrap(),
            ];

            let mut agg_circuit = X509VerifierAggregationCircuit::new(
                CircuitBuilderStage::Keygen,
                AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
                &agg_params,
                snarks.clone(),
                VerifierUniversality::Full
            );

            let agg_config = agg_circuit.calculate_params(Some(10));

            let break_points = agg_circuit.break_points();

            let agg_circuit = X509VerifierAggregationCircuit::new(
                CircuitBuilderStage::Prover,
                agg_config,
                &agg_params,
                snarks,
                VerifierUniversality::Full,
            ).use_break_points(break_points.clone());

            let pk = read_pk::<AggregationCircuit>(Path::new(&pk_path), agg_circuit.params()).unwrap();
            let num_instances = agg_circuit.num_instance();
            let instances = agg_circuit.instances();
            let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
                &agg_params,
                pk.get_vk(),
                num_instances,
                Some(Path::new("X509AggregationVerifierFinal.sol")),
            );

            let proof = gen_evm_proof_shplonk(&agg_params, &pk, agg_circuit, instances.clone());

            println!("Size of the contract: {} bytes", deployment_code.len());

            evm_verify(deployment_code, instances, proof);
        }
    }
}