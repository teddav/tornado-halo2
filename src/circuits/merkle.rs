use crate::chips::merkle::{MerkleChip, MerkleConfig};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::ff::PrimeField,
    plonk::{Circuit, ConstraintSystem},
};

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
        let root_cell = chip.prove_tree_root(
            layouter.namespace(|| "prove tree"),
            leaf_cell,
            self.path_elements.clone(),
            self.path_indices.clone(),
        )?;
        layouter.constrain_instance(root_cell.cell(), config.instance, 1)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};

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
