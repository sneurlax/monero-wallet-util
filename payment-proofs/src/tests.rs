use zeroize::Zeroizing;
use rand_core::OsRng;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};

use monero_wallet::{
  address::Network,
  ViewPair,
  ed25519::{Point, Scalar as OxideScalar},
  primitives::keccak256,
  ringct::EncryptedAmount,
};

use crate::{OutProof, shared_key_derivations::SharedKeyDerivations};

#[test]
fn out_proof_serialization() {
  let spend_key = Zeroizing::new(Scalar::random(&mut OsRng));
  let view_key = Zeroizing::new(Scalar::random(&mut OsRng));
  let view_pair = ViewPair::new(
    Point::from(ED25519_BASEPOINT_TABLE * &*spend_key),
    Zeroizing::new(OxideScalar::from(*view_key)),
  )
  .unwrap();

  let ephemeral_key = Zeroizing::new(Scalar::random(&mut OsRng));

  let proof =
    OutProof::prove(&mut OsRng, &view_pair.legacy_address(Network::Mainnet), &ephemeral_key, &[]);

  let mut proofs = vec![];
  for _ in 0 .. 5 {
    assert_eq!(&OutProof::read(&OutProof::serialize(&proofs)).unwrap(), &proofs);
    proofs.push(proof);
  }
}

#[test]
fn decrypt_original_amount() {
  let hash_to_scalar = |bytes: [u8; 32]| Scalar::from_bytes_mod_order(keccak256(bytes));

  let shared_key = Scalar::from(3u8);
  let mask_key = hash_to_scalar(shared_key.to_bytes());
  // Only meaningful if the reduction changed the hash
  assert_ne!(mask_key.to_bytes(), keccak256(shared_key.to_bytes()));
  let amount_key = hash_to_scalar(mask_key.to_bytes());

  let mask = Scalar::from(5u8);
  let amount = 123_456_789u64;
  let encrypted = EncryptedAmount::Original {
    mask: (mask + mask_key).to_bytes(),
    amount: (Scalar::from(amount) + amount_key).to_bytes(),
  };

  let derivations = SharedKeyDerivations { view_tag: 0, shared_key: OxideScalar::from(shared_key) };
  let commitment = derivations.decrypt(&encrypted);
  assert_eq!(commitment.amount, amount);
  assert_eq!(<[u8; 32]>::from(commitment.mask), mask.to_bytes());
}
