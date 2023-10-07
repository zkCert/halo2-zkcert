// Generate Sha256BitCircuit
use zkevm_hashes::util::eth_types::Field;
use std::marker::PhantomData;
use zkevm_hashes::sha256::vanilla::{
    columns::Sha256CircuitConfig,
    util::get_sha2_capacity,
    witness::AssignedSha256Block,
};
use halo2_base::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    halo2curves::bn256::Fr,
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
use std::cell::RefCell;
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
    witness_gen_only: bool,
    exposed_instances: RefCell<Vec<Fr>>,
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
                
                {
                    println!("Num advice columns: 18"); // fixed at 18
                    println!("Num rows: {:?}", self.num_rows);
                }

                Ok(final_block)
            },
        )?;

        println!("is final{:?}", result.is_final());
        println!("word val{:?}", result.word_values());
        println!("output {:?}", result.output());
        println!("len {:?}", result.length());

        // Expose public
        self.expose_public(config.instance, layouter.namespace(|| "expose"), result);

        Ok(())
    }
}

impl<F: Field> Sha256BitCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(num_rows: Option<usize>, inputs: Vec<Vec<u8>>, witness_gen_only: bool) -> Self {
        Sha256BitCircuit { num_rows, inputs, witness_gen_only, exposed_instances: vec![].into(), _marker: PhantomData }
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
        for (i, input_block) in assigned_blocks.iter().enumerate() {
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
                println!("input: {:?}", true_input);
                let a = hasher.finalize().to_vec();
                println!("output: {:?}", a);
                println!("output circuit: {:?}", output);
                assert_eq!(output, a, "Outputs do not match");

                input_offset += 1;
                println!("outputoutput: {:?}", output);
                println!("outputoutput: {:?}", i);
            }
        }
    }

    fn expose_public(
        &self,
        instance_column: Column<Instance>,
        mut layouter: impl Layouter<F>,
        result: AssignedSha256Block<F>,
    ) {
        // expose public instances
        let output_lo = result.output().lo();
        let output_hi = result.output().hi();
        layouter.constrain_instance(output_lo.cell(), instance_column, 0);
        layouter.constrain_instance(output_hi.cell(), instance_column, 1);
        
        // TODO: how do you expose public instances?
        let output_lo = self.extract_value(output_lo);
        let output_hi = self.extract_value(output_hi);
        self.exposed_instances.borrow_mut().extend(output_lo.to_repr().iter().map(|x| Fr::from(*x as u64)).collect_vec());
        self.exposed_instances.borrow_mut().extend(output_hi.to_repr().iter().map(|x| Fr::from(*x as u64)).collect_vec());            

        println!("exposed_instances: {:?}", self.exposed_instances.borrow());
    }

    fn extract_value(&self, a: Halo2AssignedCell<F>) -> F {
        let value = *value_to_option(a.value()).unwrap_or(&&Assigned::Zero);
        #[cfg(feature = "halo2-axiom")]
        let value = *value;
        #[cfg(not(feature = "halo2-axiom"))]
        let value = value.clone();
        match value {
            Assigned::Trivial(v) => v,
            Assigned::Zero => F::ZERO,
            Assigned::Rational(a, b) => a * b.invert().unwrap(),
        }
    }
}

impl CircuitExt<Fr> for Sha256BitCircuit<Fr> {
    fn num_instance(&self) -> Vec<usize> {
        vec![self.exposed_instances.borrow().len()]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.exposed_instances.borrow().iter().map(|x| *x).collect_vec()]
    }
}
