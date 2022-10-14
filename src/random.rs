use std::marker::PhantomData;

use super::transcript::ProofTranscript;
use ark_ff::{PrimeField, UniformRand};
use ark_std::test_rng;
use merlin::Transcript;

pub struct RandomTape<F> {
  tape: Transcript,
  phantom: PhantomData<F>,
}

impl<F: PrimeField> RandomTape<F> {
  pub fn new(name: &'static [u8]) -> Self {
    let tape = {
      let mut prng = test_rng();
      let mut tape = Transcript::new(name);
      tape.append_scalar(b"init_randomness", &F::rand(&mut prng));
      tape
    };
    Self {
      tape,
      phantom: PhantomData,
    }
  }

  pub fn random_scalar(&mut self, label: &'static [u8]) -> F {
    self.tape.challenge_scalar(label)
  }

  pub fn random_vector(&mut self, label: &'static [u8], len: usize) -> Vec<F> {
    self.tape.challenge_vector(label, len)
  }
}
