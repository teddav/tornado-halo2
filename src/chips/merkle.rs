use crate::chips::hash::{HashChip, HashConfig};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::ff::PrimeField,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct MerkleConfig {
    pub advice: [Column<Advice>; 3],
    pub instance: Column<Instance>,
    pub swap_selector: Selector,
    pub swap_bit_bool_selector: Selector,
    pub hash_config: HashConfig,
}

pub struct MerkleChip<F> {
    pub config: MerkleConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> MerkleChip<F> {
    pub fn construct(config: MerkleConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> MerkleConfig {
        let swap_selector = meta.selector();
        let swap_bit_bool_selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);
        meta.enable_equality(advice[2]);
        meta.enable_equality(instance);

        // we check that the `swap_bit` (advice[2]) is either `0` or `1`
        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(swap_bit_bool_selector);
            let swap_bit = meta.query_advice(advice[2], Rotation::cur());
            vec![s * swap_bit.clone() * (Expression::Constant(F::from(1)) - swap_bit)]
        });

        // if the swap selector is on (on the first row)
        // then we check the `swap_bit`
        // If it's on (1) -> we make sure the leaves are swapped on the next row
        meta.create_gate("swap constraint", |meta| {
            let s = meta.query_selector(swap_selector);
            let swap_bit = meta.query_advice(advice[2], Rotation::cur());

            let left_cur = meta.query_advice(advice[0], Rotation::cur());
            let right_cur = meta.query_advice(advice[1], Rotation::cur());

            let left_next = meta.query_advice(advice[0], Rotation::next());
            let right_next = meta.query_advice(advice[1], Rotation::next());

            let constraint1 = s.clone()
                * ((right_cur.clone() - left_cur.clone()) * swap_bit.clone() + left_cur.clone()
                    - left_next);
            let constraint2 =
                s * ((left_cur - right_cur.clone()) * swap_bit + right_cur - right_next);
            vec![constraint1, constraint2]
        });

        let hash_config = HashChip::configure(meta, advice, instance);

        MerkleConfig {
            advice,
            instance,
            swap_selector,
            swap_bit_bool_selector,
            hash_config,
        }
    }

    pub fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<F>,
        node_cell: &AssignedCell<F, F>,
        neighbor: Value<F>,
        swap_bit: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let (left, right) = layouter.assign_region(
            || "merkle prove",
            |mut region| {
                self.config.swap_selector.enable(&mut region, 0)?;
                self.config.swap_bit_bool_selector.enable(&mut region, 0)?;

                node_cell.copy_advice(
                    || "copy previous node cell",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;
                region.assign_advice(
                    || "set neighbor node",
                    self.config.advice[1],
                    0,
                    || neighbor,
                )?;
                region.assign_advice(|| "set swap bit", self.config.advice[2], 0, || swap_bit)?;

                let mut left = node_cell.value().cloned();
                let mut right = neighbor;
                swap_bit.map(|f| {
                    (left, right) = if f == F::ZERO {
                        (left, right)
                    } else {
                        (right, left)
                    }
                });

                let left_cell = region.assign_advice(
                    || "left node to be hashed",
                    self.config.advice[0],
                    1,
                    || left,
                )?;
                let right_cell = region.assign_advice(
                    || "right node to be hashed",
                    self.config.advice[1],
                    1,
                    || right,
                )?;

                Ok((left_cell, right_cell))
            },
        )?;

        let hash_chip = HashChip::construct(self.config.hash_config);
        let result_hash_cell = hash_chip.hash(layouter.namespace(|| "hash row"), left, right)?;
        Ok(result_hash_cell)
    }

    pub fn prove_tree_root(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: AssignedCell<F, F>,
        path_elements: Vec<Value<F>>,
        path_indices: Vec<Value<F>>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut digest: AssignedCell<F, F> = leaf;
        for i in 0..path_elements.len() {
            digest = self.merkle_prove_layer(
                layouter.namespace(|| "prove tree"),
                &digest,
                path_elements[i],
                path_indices[i],
            )?;
        }
        Ok(digest)
    }
}
