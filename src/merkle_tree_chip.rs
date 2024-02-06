use halo2_proofs::{
    arithmetic::Field,
    plonk::{Advice, Column, ConstraintSystem, Selector},
};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
struct MerkleTreeConfig {
    advice: [Column<Advice>; 3],
    swap_selector: Selector,
}

pub struct MerkleTreeChip<F: Field> {
    config: MerkleTreeConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> MerkleTreeChip<F> {
    fn construct(config: MerkleTreeConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        swap_selector: Selector,
    ) -> MerkleTreeConfig {
        MerkleTreeConfig {
            advice,
            swap_selector,
        }
    }
}
