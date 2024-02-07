use super::{
    hash::{HashChip, HashConfig},
    merkle::{MerkleChip, MerkleConfig},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::ff::PrimeField,
    plonk::{Advice, Column, ConstraintSystem, Error, Instance},
};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct TornadoConfig {
    pub advice: [Column<Advice>; 3],
    pub instance: Column<Instance>,
    pub merkle_config: MerkleConfig,
    pub hash_config: HashConfig,
}

pub struct TornadoChip<F> {
    pub config: TornadoConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> TornadoChip<F> {
    pub fn construct(config: TornadoConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> TornadoConfig {
        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);
        meta.enable_equality(advice[2]);
        meta.enable_equality(instance);

        let merkle_config = MerkleChip::configure(meta, advice, instance);
        let hash_config = HashChip::configure(meta, advice, instance);

        TornadoConfig {
            advice,
            instance,
            merkle_config,
            hash_config,
        }
    }

    pub fn compute_hash(
        &self,
        mut layouter: impl Layouter<F>,
        left_value: Value<F>,
        right_value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let (left, right) = layouter.assign_region(
            || "compute hash",
            |mut region| {
                let left_cell =
                    region.assign_advice(|| "value 1", self.config.advice[0], 0, || left_value)?;
                let right_cell =
                    region.assign_advice(|| "value 2", self.config.advice[1], 0, || right_value)?;
                Ok((left_cell, right_cell))
            },
        )?;

        let hash_chip = HashChip::construct(self.config.hash_config);
        let hash_result = hash_chip.hash(layouter.namespace(|| "hash values"), left, right)?;
        Ok(hash_result)
    }
}
