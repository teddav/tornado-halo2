use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    halo2curves::ff::PrimeField,
    plonk::{Advice, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy)]
pub struct HashConfig {
    pub advice: [Column<Advice>; 3],
    pub instance: Column<Instance>,
    pub hash_selector: Selector,
}

pub struct HashChip<F> {
    pub config: HashConfig,
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
