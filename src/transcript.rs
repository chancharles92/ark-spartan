use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;

pub trait ProofTranscript<G:ProjectiveCurve> {
  fn append_protocol_name(&mut self, protocol_name: &'static [u8]);
  fn append_scalar(&mut self, label: &'static [u8], scalar: &G::ScalarField);
  fn append_point(&mut self, label: &'static [u8], point: &G);
  fn challenge_scalar(&mut self, label: &'static [u8]) -> G::ScalarField;
  fn challenge_vector(&mut self, label: &'static [u8], len: usize) -> Vec<G::ScalarField>;
}

impl<G: ProjectiveCurve> ProofTranscript<G> for Transcript {
  fn append_protocol_name(&mut self, protocol_name: &'static [u8]) {
    self.append_message(b"protocol-name", protocol_name);
  }

  fn append_scalar(&mut self, label: &'static [u8], scalar: &G::ScalarField) {
    let mut buf = vec![];
    scalar.serialize(&mut buf).unwrap();
    self.append_message(label, &buf);
  }

  fn append_point(&mut self, label: &'static [u8], point: &G) {
    let mut buf = vec![];
    point.serialize(&mut buf).unwrap();
    self.append_message(label, &buf);
  }

  fn challenge_scalar(&mut self, label: &'static [u8]) -> G::ScalarField {
    let mut buf = [0u8; 64];
    self.challenge_bytes(label, &mut buf);
    G::ScalarField::from_le_bytes_mod_order(&buf)
  }

  fn challenge_vector(&mut self, label: &'static [u8], len: usize) -> Vec<G::ScalarField> {
    (0..len)
      .map(|_i| self.challenge_scalar(label))
      .collect::<Vec<G::ScalarField>>()
  }
}

pub trait AppendToTranscript<G:ProjectiveCurve> {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript);
}

// impl<G:ProjectiveCurve> AppendToTranscript<G> for G::ScalarField {
//   fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
//     transcript.append_scalar(label, self);
//   }
// }

impl<G:ProjectiveCurve> AppendToTranscript<G> for [G::ScalarField] {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_message(label, b"begin_append_vector");
    for item in self {
      transcript.append_scalar(label, item);
    }
    transcript.append_message(label, b"end_append_vector");
  }
}

impl<G:ProjectiveCurve> AppendToTranscript<G> for G {
  fn append_to_transcript(&self, label: &'static [u8], transcript: &mut Transcript) {
    transcript.append_point(label, self);
  }
}
