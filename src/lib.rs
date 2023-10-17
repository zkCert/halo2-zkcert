use halo2_base::{
    gates::{
        circuit::{
            builder::BaseCircuitBuilder, BaseConfig, CircuitBuilderStage,
        },
        flex_gate::MultiPhaseThreadBreakPoints,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr},
        plonk::{self, Circuit, ConstraintSystem, Selector},
        poly::kzg::commitment::ParamsKZG,
    },
};
use snark_verifier_sdk::{
    CircuitExt,
    SHPLONK,
    halo2::aggregation::{AggregationConfigParams, VerifierUniversality, AggregationCircuit},
    Snark,
};
use itertools::Itertools;

#[cfg(test)]
mod tests;
pub mod helpers;
pub mod sha256_bit_circuit;

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

        let snark_0_instances = aggregation_circuit.previous_instances()[0].clone();
        let snark_1_instances = aggregation_circuit.previous_instances()[1].clone();
        let snark_2_instances = aggregation_circuit.previous_instances()[2].clone();
        let snark_3_instances = aggregation_circuit.previous_instances()[3].clone();
        
        snark_0_instances.iter().zip(snark_1_instances.iter()).map(|(x, y)| {
            aggregation_circuit.builder.pool(0).threads[0].constrain_equal(x, y);
        }).collect_vec();

        snark_2_instances.iter().zip(snark_3_instances.iter()).map(|(x, y)| {
            aggregation_circuit.builder.pool(0).threads[0].constrain_equal(x, y);
        }).collect_vec();

        // TODO: link cert pairs with each other

        Self {
            aggregation_circuit
        }
    }

    /// Auto-configure the circuit and change the circuit's internal configuration parameters.
    pub fn calculate_params(&mut self, minimum_rows: Option<usize>) -> AggregationConfigParams {
        self.aggregation_circuit.calculate_params(minimum_rows)
    }

    /// The break points of the circuit.
    pub fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.aggregation_circuit.break_points()
    }

    /// Sets the break points of the circuit.
    pub fn set_break_points(&mut self, break_points: MultiPhaseThreadBreakPoints) {
        self.aggregation_circuit.set_break_points(break_points);
    }

    /// Returns new with break points
    pub fn use_break_points(mut self, break_points: MultiPhaseThreadBreakPoints) -> Self {
        self.set_break_points(break_points);
        self
    }
}

impl Circuit<Fr> for X509VerifierAggregationCircuit {
    type Config = BaseConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = AggregationConfigParams;

    fn params(&self) -> Self::Params {
        (&self.aggregation_circuit.builder.config_params).try_into().unwrap()
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<Fr>,
        params: Self::Params,
    ) -> Self::Config {
        BaseCircuitBuilder::configure_with_params(meta, params.into())
    }

    fn configure(_: &mut ConstraintSystem<Fr>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        self.aggregation_circuit.synthesize(config, layouter)
    }
}

impl CircuitExt<Fr> for X509VerifierAggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        self.aggregation_circuit.num_instance()
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        self.aggregation_circuit.instances()
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        AggregationCircuit::accumulator_indices()
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        AggregationCircuit::selectors(config)
    }
}
