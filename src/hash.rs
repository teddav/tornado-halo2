use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    // arithmetic::Field,
    halo2curves::ff::PrimeField,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy)]
pub struct HashConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    hash_selector: Selector,
}

pub struct HashChip<F> {
    config: HashConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> HashChip<F> {
    pub fn construct(config: HashConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> HashConfig {
        let hash_selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);
        meta.enable_equality(advice[2]);
        meta.enable_equality(instance);

        meta.create_gate("hash constraint", |meta| {
            let s = meta.query_selector(hash_selector);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let hash_result = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a * b - hash_result)]
        });

        HashConfig {
            advice,
            instance,
            hash_selector,
        }
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        left_cell: AssignedCell<F, F>,
        right_cell: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "hash row",
            |mut region| {
                self.config.hash_selector.enable(&mut region, 0)?;

                left_cell.copy_advice(
                    || "copy left input",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;
                right_cell.copy_advice(
                    || "copy right input",
                    &mut region,
                    self.config.advice[1],
                    0,
                )?;

                let hash_result_cell = region.assign_advice(
                    || "output",
                    self.config.advice[2],
                    0,
                    || left_cell.value().cloned() * right_cell.value().cloned(),
                )?;

                Ok(hash_result_cell)
            },
        )
    }
}

#[derive(Debug, Default)]
pub struct HashCircuit<F> {
    pub a: Value<F>,
    pub b: Value<F>,
}

impl<F: PrimeField> Circuit<F> for HashCircuit<F> {
    type Config = HashConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        HashChip::configure(meta, advice, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let (left, right) = layouter.assign_region(
            || "private inputs",
            |mut region| {
                let left = region.assign_advice(
                    || "private input left",
                    config.advice[0],
                    0,
                    || self.a,
                )?;
                let right = region.assign_advice(
                    || "private input right",
                    config.advice[1],
                    0,
                    || self.b,
                )?;
                Ok((left, right))
            },
        )?;

        let chip = HashChip::construct(config);
        let hash_result_cell = chip.hash(layouter.namespace(|| "hasher"), left, right)?;

        layouter.constrain_instance(hash_result_cell.cell(), config.instance, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::HashCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};

    #[test]
    fn test_hash_circuit() {
        let a = 11;
        let b = 7;

        let circuit = HashCircuit {
            a: Value::known(Fp::from(a)),
            b: Value::known(Fp::from(b)),
        };
        let public_inputs = vec![Fp::from(a * b)];
        let prover = MockProver::run(4, &circuit, vec![public_inputs.clone()]).unwrap();
        assert!(prover.verify().is_ok());

        let public_inputs2 = vec![Fp::from(a * b + 1)];
        let prover2 = MockProver::run(4, &circuit, vec![public_inputs2.clone()]).unwrap();
        assert!(prover2.verify().is_err());
    }
}
