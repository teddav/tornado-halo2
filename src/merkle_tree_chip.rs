use crate::hash::{HashChip, HashConfig};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::ff::PrimeField,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct MerkleConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    swap_selector: Selector,
    swap_bit_bool_selector: Selector,
    hash_config: HashConfig,
}

pub struct MerkleChip<F: PrimeField> {
    config: MerkleConfig,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> MerkleChip<F> {
    fn construct(config: MerkleConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
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

    fn merkle_prove(
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
}

#[derive(Debug, Default)]
pub struct MerkleCircuit<F> {
    pub leaf: Value<F>,
    pub path_elements: Vec<Value<F>>,
    pub path_indices: Vec<Value<F>>,
}

impl<F: PrimeField> Circuit<F> for MerkleCircuit<F> {
    type Config = MerkleConfig;
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
        MerkleChip::configure(meta, advice, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let leaf_cell = layouter.assign_region(
            || "assign leaf",
            |mut region| region.assign_advice(|| "assign leaf", config.advice[0], 0, || self.leaf),
        )?;
        layouter.constrain_instance(leaf_cell.cell(), config.clone().instance, 0)?;

        let chip = MerkleChip::construct(config.clone());
        let mut digest: AssignedCell<F, F> = leaf_cell;
        for i in 0..self.path_elements.len() {
            digest = chip.merkle_prove(
                layouter.namespace(|| "prove tree"),
                &digest,
                self.path_elements[i],
                self.path_indices[i],
            )?;
        }

        layouter.constrain_instance(digest.cell(), config.instance, 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};

    use super::MerkleCircuit;

    #[test]
    fn test_merkle_circuit() {
        let leaf = 123;
        let elements = vec![2, 7, 6, 5, 5, 4];
        let indices = vec![0, 1, 1, 0, 1, 0];
        let root = leaf * elements.iter().product::<u64>();

        let circuit = MerkleCircuit {
            leaf: Value::known(Fp::from(leaf)),
            path_elements: elements
                .iter()
                .map(|e| Value::known(Fp::from(*e)))
                .collect(),
            path_indices: indices.iter().map(|e| Value::known(Fp::from(*e))).collect(),
        };
        let public_input = vec![Fp::from(leaf), Fp::from(root)];
        let prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn test_merkle_circuit_err() {
        let leaf = 123;
        let elements = vec![2, 7, 6, 5, 5, 4];
        let indices = vec![0, 1, 1, 0, 1, 2];
        let root = leaf * elements.iter().product::<u64>();

        let circuit = MerkleCircuit {
            leaf: Value::known(Fp::from(leaf)),
            path_elements: elements
                .iter()
                .map(|e| Value::known(Fp::from(*e)))
                .collect(),
            path_indices: indices.iter().map(|e| Value::known(Fp::from(*e))).collect(),
        };
        let public_input = vec![Fp::from(leaf), Fp::from(root)];
        let prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();
        assert!(prover.verify().is_err());

        let public_input2 = vec![Fp::from(leaf), Fp::from(root + 1)];
        let prover2 = MockProver::run(10, &circuit, vec![public_input2]).unwrap();
        assert!(prover2.verify().is_err());
    }
}
