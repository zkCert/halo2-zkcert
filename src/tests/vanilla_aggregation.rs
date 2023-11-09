use halo2_base::{
    halo2_proofs::{dev::MockProver, halo2curves::{bn256::Fr, ff::PrimeField}},
    gates::circuit::CircuitBuilderStage,
    utils::fs::gen_srs
};
use snark_verifier_sdk::{
    CircuitExt,
    SHPLONK,
    gen_pk,
    halo2::{aggregation::{AggregationConfigParams, VerifierUniversality, AggregationCircuit}, gen_snark_shplonk},
};
use crate::sha256_bit_circuit::Sha256BitCircuit;
use crate::helpers::*;
use std::vec;

#[test]
fn test_aggregation_split_zkevm_sha256_rsa() {
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

    // Create an aggregation circuit using the snark
    let agg_k = 20;
    let agg_lookup_bits = agg_k - 1;
    let agg_params = gen_srs(agg_k as u32);
    let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
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
        vec![snark1, snark2, snark3, snark4],
        VerifierUniversality::Full,
    ).use_break_points(break_points.clone());

    println!("Generating aggregation snark");
    let _agg_snark = gen_snark_shplonk(&agg_params, &pk, agg_circuit, None::<&str>);
    println!("Aggregation snark success");
}


#[test]
fn test_generate_zkevm_sha256() {
    let k = 11;
    let (tbs, _) = extract_tbs_and_sig("./certs/example_cert_3.pem");

    let mut sha256_bit_circuit = Sha256BitCircuit::new(
        Some(2usize.pow(k as u32) - 109),
        vec![tbs.to_vec()],
        false
    );
    sha256_bit_circuit.set_instances(vec![
        Fr::from_u128(0x00000000000000000000000000000000eeb16b6a466d78243f0210594c79e2ea),
        Fr::from_u128(0x000000000000000000000000000000005773a131a99b9c98158c743ebd7e521a)
    ]);
    MockProver::run(k as u32, &sha256_bit_circuit, sha256_bit_circuit.instances()).unwrap().assert_satisfied();
}

#[test]
fn test_generate_rsa_4096() {
    let k = 16;
    let (tbs, signature_bigint) = extract_tbs_and_sig("./certs/example_cert_2.pem");
    let default_bits = 4096;

    let public_key_modulus = extract_public_key("./certs/example_cert_1.pem");

    let builder = create_default_rsa_circuit_with_instances(k, default_bits, tbs, public_key_modulus, signature_bigint, false, vec![vec![]]);

    MockProver::run(k as u32, &builder, builder.instances()).unwrap().assert_satisfied();
}

#[test]
fn test_generate_rsa_2048() {
    let k = 16;
    let (tbs, signature_bigint) = extract_tbs_and_sig("./certs/example_cert_3.pem");
    let default_bits = 2048;

    let public_key_modulus = extract_public_key("./certs/example_cert_2.pem");

    let builder = create_default_rsa_circuit_with_instances(k, default_bits, tbs, public_key_modulus, signature_bigint, false, vec![vec![]]);

    MockProver::run(k as u32, &builder, builder.instances()).unwrap().assert_satisfied();
}