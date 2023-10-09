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
// use itertools::Itertools;

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
        let aggregation_circuit = AggregationCircuit::new::<SHPLONK>(
            stage,
            config_params,
            params,
            snarks.clone(),
            universality,
        );

        // TODO: zkevm SHA256 vanilla snarks don't expose instances so this custom aggregation circuit doesn't work. Need to debug
        println!("prev instances: {:?}", aggregation_circuit.previous_instances());

        let instances = aggregation_circuit.previous_instances()[0].clone();

        println!("instances: {:?}", instances);

        // for i in 0..snarks[0].instances.len() {
        //     snarks[0].instances[i].iter().zip(snarks[1].instances[i].iter()).map(|(x, y)| {
        //         let x = aggregation_circuit.builder.pool(0).threads[0].load_witness(*x);
        //         let y = aggregation_circuit.builder.pool(0).threads[0].load_witness(*y);
        //         aggregation_circuit.builder.pool(0).threads[0].constrain_equal(&x, &y);
        //     }).collect_vec();
        // }
        // for i in 0..snarks[2].instances.len() {
        //     snarks[2].instances[i].iter().zip(snarks[3].instances[i].iter()).map(|(x, y)| {
        //         let x = aggregation_circuit.builder.pool(0).threads[0].load_witness(*x);
        //         let y = aggregation_circuit.builder.pool(0).threads[0].load_witness(*y);
        //         aggregation_circuit.builder.pool(0).threads[0].constrain_equal(&x, &y);
        //     }).collect_vec();
        // }

        Self {
            aggregation_circuit
        }
    }
}