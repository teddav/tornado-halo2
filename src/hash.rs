use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Instance, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct HashConfig {
    advice: [Column<Advice>; 2],
    instance: Column<Instance>,
    hash_selector: Selector,
}

struct HashChip<F: Field> {
    config: HashConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> HashChip<F> {
    fn construct(config: HashConfig) -> Self {
        println!("chip construct");

        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
    ) -> HashConfig {
        println!("chip config");

        let hash_selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);
        meta.enable_equality(instance);

        meta.create_gate("hash", |meta| {
            let s = meta.query_selector(hash_selector);
            let n = meta.query_advice(advice[0], Rotation::cur());
            let hashed_value = meta.query_advice(advice[1], Rotation::cur());
            vec![s * (n.clone() * n - hashed_value)]
        });

        HashConfig {
            advice,
            instance,
            hash_selector,
        }
    }
}

#[derive(Debug, Default)]
pub struct HashCircuit<F: Field> {
    pub n: Value<F>,
}

impl<F: Field> Circuit<F> for HashCircuit<F> {
    type Config = HashConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        println!("circuit config");
        let advice = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        HashChip::configure(meta, advice, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        println!("circuit synthesize");
        // let chip = HashChip::construct(config);

        let output_hash_value_cell = layouter.assign_region(
            || "hash preimage",
            |mut region| {
                config.hash_selector.enable(&mut region, 0)?;
                region.assign_advice(|| "private input", config.advice[0], 0, || self.n)?;
                let output_hash_value_cell =
                    region.assign_advice(|| "output", config.advice[1], 0, || self.n * self.n)?;
                Ok(output_hash_value_cell)
            },
        )?;

        layouter.constrain_instance(output_hash_value_cell.cell(), config.instance, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::HashCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};

    #[test]
    fn test_hash_circuit() {
        let n = 12;
        let circuit = HashCircuit {
            n: Value::known(Fp::from(n)),
        };
        let public_inputs = vec![Fp::from(n * n)];
        let prover = MockProver::run(4, &circuit, vec![public_inputs.clone()]).unwrap();
        assert!(prover.verify().is_ok());

        let public_inputs2 = vec![Fp::from(n * n * n)];
        let prover2 = MockProver::run(4, &circuit, vec![public_inputs2.clone()]).unwrap();
        assert!(prover2.verify().is_err());
    }
}
