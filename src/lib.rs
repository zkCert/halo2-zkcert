use halo2_base::{
    gates::circuit::CircuitBuilderStage,
    halo2_proofs::{
        halo2curves::bn256::Bn256,
        poly::kzg::commitment::ParamsKZG,
    },
};
use snark_verifier_sdk::{
    SHPLONK,
    halo2::aggregation::{AggregationConfigParams, VerifierUniversality, AggregationCircuit},
    Snark,
};
use itertools::Itertools;

#[cfg(test)]
mod tests;

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

        // TODO: zkevm SHA256 vanilla snarks don't expose instances so this custom aggregation circuit doesn't work. Need to debug
        let snark_0_instances = aggregation_circuit.previous_instances()[0].clone();
        let snark_1_instances = aggregation_circuit.previous_instances()[1].clone();
        let snark_2_instances = aggregation_circuit.previous_instances()[2].clone();
        let snark_3_instances = aggregation_circuit.previous_instances()[3].clone();
        
        snark_0_instances.iter().zip(snark_1_instances.iter()).map(|(x, y)| {
            println!("x: {:?}, y: {:?}", x, y);
            aggregation_circuit.builder.pool(0).threads[0].constrain_equal(&x, &y);
        }).collect_vec();

        snark_2_instances.iter().zip(snark_3_instances.iter()).map(|(x, y)| {
            println!("x: {:?}, y: {:?}", x, y);
            aggregation_circuit.builder.pool(0).threads[0].constrain_equal(&x, &y);
        }).collect_vec();

        Self {
            aggregation_circuit
        }
    }
}