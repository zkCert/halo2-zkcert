// use halo2_base::{
//     gates::circuit::CircuitBuilderStage,
//     utils::fs::gen_srs
// };
// use snark_verifier_sdk::{
//     SHPLONK,
//     gen_pk,
//     halo2::{aggregation::{AggregationConfigParams, VerifierUniversality, AggregationCircuit}, gen_snark_shplonk},
// };
// use crate::helpers::*;
// use std::vec;

// #[test]
// fn test_aggregation_split_zkevm_sha256_rsa1() {
//     println!("Generating dummy snark");
//     let snark1 = generate_zkevm_sha256_circuit(
//         "./certs/example_cert_3.pem",
//         11
//     );
//     let snark2 = generate_rsa_circuit_with_instances(
//         "./certs/example_cert_3.pem",
//         "./certs/example_cert_2.pem",
//         16
//     );

//     // Create an aggregation circuit using the snark
//     let agg_k = 20;
//     let agg_lookup_bits = agg_k - 1;
//     let agg_params = gen_srs(agg_k as u32);
//     let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
//         CircuitBuilderStage::Keygen,
//         AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
//         &agg_params,
//         vec![snark1.clone(), snark2.clone()],
//         VerifierUniversality::Full
//     );

//     println!("Aggregation circuit calculating params");
//     let agg_config = agg_circuit.calculate_params(Some(10));

//     // let start0 = start_timer!(|| "gen vk & pk");
//     println!("Aggregation circuit generating pk");
//     let pk = gen_pk(&agg_params, &agg_circuit, None);
    
//     let break_points = agg_circuit.break_points();

//     // std::fs::remove_file(Path::new("examples/agg.pk")).ok();
//     // let _pk = gen_pk(&params, &agg_circuit, Some(Path::new("examples/agg.pk")));
//     // end_timer!(start0);
//     // let pk = read_pk::<AggregationCircuit>(Path::new("examples/agg.pk"), agg_config).unwrap();
//     // std::fs::remove_file(Path::new("examples/agg.pk")).ok();
//     // let break_points = agg_circuit.break_points();

//     let agg_circuit = AggregationCircuit::new::<SHPLONK>(
//         CircuitBuilderStage::Prover,
//         agg_config,
//         &agg_params,
//         vec![snark1, snark2],
//         VerifierUniversality::Full,
//     ).use_break_points(break_points.clone());

//     println!("Generating aggregation snark");
//     let _agg_snark = gen_snark_shplonk(&agg_params, &pk, agg_circuit, None::<&str>);
//     println!("Aggregation snark success");
// }

// #[test]
// fn test_aggregation_split_zkevm_sha256_rsa2() {
//     println!("Generating dummy snark");
//     let snark1 = generate_zkevm_sha256_circuit(
//         "./certs/example_cert_2.pem",
//         11
//     );
//     let snark2 = generate_rsa_circuit_with_instances(
//         "./certs/example_cert_2.pem",
//         "./certs/example_cert_1.pem",
//         16
//     );

//     // Create an aggregation circuit using the snark
//     let agg_k = 20;
//     let agg_lookup_bits = agg_k - 1;
//     let agg_params = gen_srs(agg_k as u32);
//     let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
//         CircuitBuilderStage::Keygen,
//         AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
//         &agg_params,
//         vec![snark1.clone(), snark2.clone()],
//         VerifierUniversality::Full
//     );

//     println!("Aggregation circuit calculating params");
//     let agg_config = agg_circuit.calculate_params(Some(10));

//     // let start0 = start_timer!(|| "gen vk & pk");
//     println!("Aggregation circuit generating pk");
//     let pk = gen_pk(&agg_params, &agg_circuit, None);
    
//     let break_points = agg_circuit.break_points();

//     // std::fs::remove_file(Path::new("examples/agg.pk")).ok();
//     // let _pk = gen_pk(&params, &agg_circuit, Some(Path::new("examples/agg.pk")));
//     // end_timer!(start0);
//     // let pk = read_pk::<AggregationCircuit>(Path::new("examples/agg.pk"), agg_config).unwrap();
//     // std::fs::remove_file(Path::new("examples/agg.pk")).ok();
//     // let break_points = agg_circuit.break_points();

//     let agg_circuit = AggregationCircuit::new::<SHPLONK>(
//         CircuitBuilderStage::Prover,
//         agg_config,
//         &agg_params,
//         vec![snark1, snark2],
//         VerifierUniversality::Full,
//     ).use_break_points(break_points.clone());

//     println!("Generating aggregation snark");
//     let _agg_snark = gen_snark_shplonk(&agg_params, &pk, agg_circuit, None::<&str>);
//     println!("Aggregation snark success");
// }

// #[test]
// fn test_aggregation_split_zkevm_sha256_rsa3() {
//     println!("Generating dummy snark");
//     let (rsa_pk, break_points) = generate_rsa_pk(
//         "./certs/example_cert_3.pem",
//         "./certs/example_cert_2.pem",
//         16
//     );
//     let snark1 = generate_zkevm_sha256_circuit(
//         "./certs/example_cert_3.pem",
//         11
//     );
//     let snark2 = generate_rsa_proof(
//         "./certs/cert_3.pem",
//         "./certs/cert_2.pem",
//         16,
//         rsa_pk.clone(),
//         break_points.clone()
//     );
//     let snark3 = generate_zkevm_sha256_circuit(
//         "./certs/example_cert_2.pem",
//         11
//     );
//     let snark4 = generate_rsa_proof(
//         "./certs/cert_2.pem",
//         "./certs/cert_1.pem",
//         16,
//         rsa_pk.clone(),
//         break_points.clone()
//     );

//     // Create an aggregation circuit using the snark
//     let agg_k = 20;
//     let agg_lookup_bits = agg_k - 1;
//     let agg_params = gen_srs(agg_k as u32);
//     let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
//         CircuitBuilderStage::Keygen,
//         AggregationConfigParams {degree: agg_k, lookup_bits: agg_lookup_bits as usize, ..Default::default()},
//         &agg_params,
//         vec![snark1.clone(), snark2.clone(), snark3.clone(), snark4.clone()],
//         VerifierUniversality::Full
//     );

//     println!("Aggregation circuit calculating params");
//     let agg_config = agg_circuit.calculate_params(Some(10));

//     // let start0 = start_timer!(|| "gen vk & pk");
//     println!("Aggregation circuit generating pk");
//     let pk = gen_pk(&agg_params, &agg_circuit, None);
    
//     let break_points = agg_circuit.break_points();

//     // std::fs::remove_file(Path::new("examples/agg.pk")).ok();
//     // let _pk = gen_pk(&params, &agg_circuit, Some(Path::new("examples/agg.pk")));
//     // end_timer!(start0);
//     // let pk = read_pk::<AggregationCircuit>(Path::new("examples/agg.pk"), agg_config).unwrap();
//     // std::fs::remove_file(Path::new("examples/agg.pk")).ok();
//     // let break_points = agg_circuit.break_points();

//     let agg_circuit = AggregationCircuit::new::<SHPLONK>(
//         CircuitBuilderStage::Prover,
//         agg_config,
//         &agg_params,
//         vec![snark1, snark2, snark3, snark4],
//         VerifierUniversality::Full,
//     ).use_break_points(break_points.clone());

//     println!("Generating aggregation snark");
//     let _agg_snark = gen_snark_shplonk(&agg_params, &pk, agg_circuit, None::<&str>);
//     println!("Aggregation snark success");
// }


// #[test]
// fn test_generate_zkevm_sha256() {
//     println!("Generating dummy snark");
//     generate_zkevm_sha256_circuit(
//         "./certs/example_cert_3.pem",
//         11
//     );
// }


// #[test]
// fn test_generate_rsa() {
//     println!("Generating dummy snark");
//     generate_rsa_circuit_with_instances(
//         "./certs/example_cert_3.pem",
//         "./certs/example_cert_2.pem",
//         16
//     );
// }
