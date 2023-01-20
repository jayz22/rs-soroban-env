use dusk_plonk::prelude::*;

// Implement a circuit that checks:
// a + b + c < D where D is a PI
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

        // computes `lhs = a + b + c` this is not a bug, assign c to witness d
        let constraint = Constraint::new().left(1).right(1).fourth(1).a(a).b(b).d(c);
        let lhs = composer.gate_add(constraint);

        // computes `diff = lhs - d`
        let constraint2 = Constraint::new()
            .left(1)
            .right(-BlsScalar::one())
            .a(lhs)
            .b(d);
        let diff = composer.gate_add(constraint2);
        let constraint3 = Constraint::new().left(1).right(1).a(diff);
        composer.append_gate(constraint3);

        // Below is my failed attempt to assert the diff < 0.
        // let bits: [Witness; 64] = composer.component_decomposition(diff);
        // let sign_bit = bits[0];
        // let one = composer.append_constant(BlsScalar::one());
        // let constraint4 = Constraint::new()
        //     .left(1)
        //     .right(-BlsScalar::one())
        //     .a(sign_bit)
        //     .b(one);
        // composer.append_gate(constraint4);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![self.c.into()]
    }

    fn padded_gates(&self) -> usize {
        1 << 11
    }
}
