use zkevm_hashes::util::eth_types::Field;
use std::marker::PhantomData;
use zkevm_hashes::sha256::vanilla::{
    columns::Sha256CircuitConfig,
    util::get_sha2_capacity,
    witness::AssignedSha256Block,
};
use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    plonk::Circuit,
};
use halo2_base::{
    halo2_proofs::{
        circuit::Layouter,
        plonk::{Assigned, ConstraintSystem, Column, Instance, Error},
    },
    utils::{
        halo2::Halo2AssignedCell,
        value_to_option,
    },
};
use sha2::{Digest, Sha256};
use snark_verifier_sdk::CircuitExt;
use itertools::Itertools;

#[derive(Clone)]
pub struct Sha256BitCircuitConfig<F: Field> {
    sha256_circuit_config: Sha256CircuitConfig<F>,
    #[allow(dead_code)]
    instance: Column<Instance>,
}

#[derive(Default)]
pub struct Sha256BitCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
    assigned_instances: Vec<Vec<F>>,
    witness_gen_only: bool,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for Sha256BitCircuit<F> {
    type Config = Sha256BitCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let sha256_circuit_config = Sha256CircuitConfig::new(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self::Config { sha256_circuit_config, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let result = layouter.assign_region(
            || "SHA256 Bit Circuit",
            |mut region| {
                let start = std::time::Instant::now();
                let blocks = config.sha256_circuit_config.multi_sha256(
                    &mut region,
                    self.inputs.clone(),
                    self.num_rows.map(get_sha2_capacity),
                );
                println!("Witness generation time: {:?}", start.elapsed());
                // Find the block where the final output is
                let mut final_block = blocks[0].clone();
                if self.witness_gen_only {
                    self.verify_output(&blocks);
                    for assigned_blocks in blocks {
                        let value = **value_to_option(assigned_blocks.is_final().value()).unwrap();
                        let value = match value {
                            Assigned::Trivial(v) => v,
                            Assigned::Zero => F::ZERO,
                            Assigned::Rational(a, b) => a * b.invert().unwrap(),
                        };
                        if value == F::ONE {
                            final_block = assigned_blocks;
                            break;
                        }
                    }
                }
                
                let result = [
                    final_block.output().lo().clone(),
                    final_block.output().hi().clone(),
                    ];
                    {
                        println!("Num rows: {:?}", self.num_rows);
                    }
                    
                    Ok(result)
                },
            )?;

        if !self.witness_gen_only {
            // expose public instances
            let mut layouter = layouter.namespace(|| "expose");
            layouter.constrain_instance(result[0].cell(), config.instance, 0);
            layouter.constrain_instance(result[1].cell(), config.instance, 1);
        }

        Ok(())
    }
}

impl<F: Field> Sha256BitCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(
        num_rows: Option<usize>,
        inputs: Vec<Vec<u8>>,
        witness_gen_only: bool
    ) -> Self {
        Sha256BitCircuit { num_rows, inputs, witness_gen_only, assigned_instances: vec![vec![]], _marker: PhantomData }
    }

    pub fn set_instances(
        &mut self,
        instances: Vec<F>,
    ) {
        self.assigned_instances[0].extend(instances);
    }

    fn verify_output(&self, assigned_blocks: &[AssignedSha256Block<F>]) {
        let mut input_offset = 0;
        let mut input = vec![];
        let extract_value = |a: Halo2AssignedCell<F>| {
            let value = *value_to_option(a.value()).unwrap();
            #[cfg(feature = "halo2-axiom")]
            let value = *value;
            #[cfg(not(feature = "halo2-axiom"))]
            let value = value.clone();
            match value {
                Assigned::Trivial(v) => v,
                Assigned::Zero => F::ZERO,
                Assigned::Rational(a, b) => a * b.invert().unwrap(),
            }
        };
        for input_block in assigned_blocks {
            let is_final = input_block.is_final().clone();
            let output = input_block.output().clone();
            let word_values = input_block.word_values().clone();
            let length = input_block.length().clone();
            let [is_final, output_lo, output_hi, length] =
                [is_final, output.lo(), output.hi(), length].map(extract_value);
            let word_values = word_values.iter().cloned().map(extract_value).collect::<Vec<_>>();
            for word in word_values {
                let word = word.get_lower_32().to_le_bytes();
                input.extend_from_slice(&word);
            }
            let is_final = is_final == F::ONE;
            if is_final {
                let empty = vec![];
                let true_input = self.inputs.get(input_offset).unwrap_or(&empty);
                let true_length = true_input.len();
                assert_eq!(length.get_lower_64(), true_length as u64, "Length does not match");
                // clear global input and make it local
                let mut input = std::mem::take(&mut input);
                input.truncate(true_length);
                assert_eq!(&input, true_input, "Inputs do not match");
                let output_lo = output_lo.to_repr(); // u128 as 32 byte LE
                let output_hi = output_hi.to_repr();
                let mut output = [&output_lo[..16], &output_hi[..16]].concat();
                output.reverse(); // = [output_hi_be, output_lo_be].concat()

                let mut hasher = Sha256::new();
                hasher.update(true_input);
                let a = hasher.finalize().to_vec();
                assert_eq!(output, a, "Outputs do not match");

                input_offset += 1;
            }
        }
    }

}

impl<F: Field> CircuitExt<F> for Sha256BitCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        self.assigned_instances.iter().map(|instances| instances.len()).collect_vec()
    }

    fn instances(&self) -> Vec<Vec<F>> {
        self.assigned_instances.clone()
    }
}