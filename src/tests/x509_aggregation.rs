use crate::X509VerifierAggregationCircuit;
use crate::helpers::*;
use std::path::Path;

use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    utils::fs::gen_srs
};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::{AggregationConfigParams, VerifierUniversality, AggregationCircuit}, gen_snark_shplonk},
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
    CircuitExt
};
use std::vec;

#[test]
fn test_x509_verifier_aggregation_circuit_evm_verification1() {
    println!("Generating dummy snark");
    let sha256_pk = generate_zkevm_sha256_pk("./certs/example_cert_3.pem", 11);
    // End vs intermediate certificates uses different RSA bits so need 2 pks
    let (rsa_pk_2048, break_points_2048) = generate_rsa_pk(
        "./certs/example_cert_3.pem",
        "./certs/example_cert_2.pem",
        17,
        2048
    );
    let (rsa_pk_4096, break_points_4096) = generate_rsa_pk(
        "./certs/example_cert_2.pem",
        "./certs/example_cert_1.pem",
        17,
        4096
    );
    let snark1 = generate_zkevm_sha256_proof(
        "./certs/example_cert_3.pem",
        11,
        sha256_pk.clone()
    );
    let snark2 = generate_rsa_proof(
        "./certs/example_cert_3.pem",
        "./certs/example_cert_2.pem",
        17,
        rsa_pk_2048,
        break_points_2048,
        2048
    );
    let snark3 = generate_zkevm_sha256_proof(
        "./certs/example_cert_2.pem",
        11,
        sha256_pk.clone()
    );
    let snark4 = generate_rsa_proof(
        "./certs/example_cert_2.pem",
        "./certs/example_cert_1.pem",
        17,
        rsa_pk_4096,
        break_points_4096,
        4096
    );

    // Create custom aggregation circuit using the snark that verifiers input of signature algorithm is same as output of hash function
    let agg_k = 22;
    let agg_lookup_bits = agg_k - 1;
    let agg_params = gen_srs(agg_k as u32);
    let mut agg_circuit = X509VerifierAggregationCircuit::new(
        CircuitBuilderStage::Keygen,
        AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
        &agg_params,
        vec![snark1.clone(), snark2.clone(), snark3.clone(), snark4.clone()],
        VerifierUniversality::Full
    );

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
    ).use_break_points(break_points.clone());

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
