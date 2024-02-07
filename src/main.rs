use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::{ff::PrimeField, pasta::Fp},
    plonk::{Circuit, ConstraintSystem, Error},
};
use tornado_halo2::chips::{
    merkle::MerkleChip,
    tornado::{TornadoChip, TornadoConfig},
};

#[derive(Debug, Default)]
pub struct TornadoCircuit<F> {
    nullifier: Value<F>,
    secret: Value<F>,
    path_elements: Vec<Value<F>>,
    path_indices: Vec<Value<F>>,
}

impl<F: PrimeField> Circuit<F> for TornadoCircuit<F> {
    type Config = TornadoConfig;
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
        TornadoChip::configure(meta, advice, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let tornado_chip = TornadoChip::construct(config.clone());

        // step 1: nullifier hash
        let nullifier_hash_cell = tornado_chip.compute_hash(
            layouter.namespace(|| "get nullifier hash"),
            self.nullifier,
            self.nullifier,
        )?;
        println!("nullifier_hash_cell {nullifier_hash_cell:?}");
        layouter.constrain_instance(nullifier_hash_cell.cell(), config.clone().instance, 0)?;

        // step 2: compute commitment
        let commitment_hash_cell = tornado_chip.compute_hash(
            layouter.namespace(|| "get nullifier hash"),
            self.nullifier,
            self.secret,
        )?;
        println!("commitment_hash_cell {commitment_hash_cell:?}");
        let merkle_chip = MerkleChip::construct(config.clone().merkle_config);
        let merkle_root_cell = merkle_chip.prove_tree_root(
            layouter.namespace(|| "prove merkle tree"),
            commitment_hash_cell,
            self.path_elements.clone(),
            self.path_indices.clone(),
        )?;
        println!("merkle_root_cell: {merkle_root_cell:?}");
        layouter.constrain_instance(merkle_root_cell.cell(), config.clone().instance, 1)?;

        Ok(())
    }
}

fn main() {
    let nullifier = Fp::from(0x456);
    let secret = Fp::from(0xabc);
    let path_elements: Vec<Fp> = vec![2, 5, 7, 14, 23].iter().map(|e| Fp::from(*e)).collect();
    let path_indices: Vec<Fp> = vec![0, 0, 1, 1, 0].iter().map(|e| Fp::from(*e)).collect();

    let circuit = TornadoCircuit {
        nullifier: Value::known(nullifier),
        secret: Value::known(secret),
        path_elements: path_elements.iter().map(|e| Value::known(*e)).collect(),
        path_indices: path_indices.iter().map(|e| Value::known(*e)).collect(),
    };

    let commitment = hash_values(vec![nullifier, secret]);
    println!("commitment {:?}", commitment);

    let root = compute_root(commitment, path_elements, path_indices);
    println!("root {:?}", root);

    let nullifier_hash = hash_value(nullifier);
    println!("nullifier_hash {:?}", nullifier_hash);

    let public_input = vec![nullifier_hash, root];
    let prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

    println!("MAIN prover: {:?}", prover.verify());
    // assert!(prover.verify().is_ok());
}

fn hash_value(value: Fp) -> Fp {
    hash_values(vec![value, value])
}
fn hash_values(values: Vec<Fp>) -> Fp {
    values.iter().product()
}

fn compute_root(leaf: Fp, path_elements: Vec<Fp>, path_indices: Vec<Fp>) -> Fp {
    assert!(path_elements.len() == path_indices.len());

    let mut node = leaf;
    for i in 0..path_elements.len() {
        let mut left = node;
        let mut right = path_elements[i];

        (left, right) = if path_indices[i] == Fp::ZERO {
            (left, right)
        } else {
            (right, left)
        };

        node = hash_values(vec![left, right]);
    }
    node
}
