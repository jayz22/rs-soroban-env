use dusk_plonk::prelude::*;

/// [`BlackJack`] is a simple arithmetic circuit that mimics a blackjack game:
/// `a`, `b`, `c` are secret witnesses that represents three cards
/// `d` is a bool decision: 0 is STAND, 1 is HIT
/// A HIT is allowed only if  `a + b + c < 21`
#[derive(Debug, Default)]
pub struct BlackJack {
    pub(crate) a: BlsScalar,
    pub(crate) b: BlsScalar,
    pub(crate) c: BlsScalar,
    pub(crate) d: BlsScalar,
}

impl Circuit for BlackJack {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), Error> {
        let a = composer.append_witness(self.a);
        let b = composer.append_witness(self.b);
        let c = composer.append_witness(self.c);
        let d = composer.append_public_witness(self.d);

        // Make first constraint a + b + c + 42
        let constraint = Constraint::new()
            .left(1)
            .right(1)
            .fourth(1)
            .constant(42u64)
            .a(a)
            .b(b)
            .d(c);
        let sum = composer.gate_add(constraint);

        // Check that sum is in range
        // e.g. if num_bits == 6, then sum < 2^6 = 64.
        composer.component_range(sum, 6);
        // check d is boolean
        composer.component_boolean(d);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![self.d.into()]
    }

    fn padded_gates(&self) -> usize {
        1 << 11
    }
}
