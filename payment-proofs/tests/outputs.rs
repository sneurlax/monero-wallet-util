//! OutProof::verify against synthetic transactions.

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
use rand_core::OsRng;
use zeroize::Zeroizing;
use monero_payment_proofs::OutProof;
use monero_wallet::{
  address::{MoneroAddress, Network},
  ed25519::{CompressedPoint, Point, Commitment, Scalar as OxideScalar},
  ringct::{EncryptedAmount, RctBase, RctProofs, RctPrunable},
  transaction::{Input, Output, Transaction, TransactionPrefix, Timelock},
  primitives::keccak256,
};

#[test]
fn verifies_owned_outputs_and_rejects_wrong_messages_keys_and_indexes() {
  for encoded_address in [
    "4AR4MfJR1FwJ49U1vqS5PCQgDRF9DjpoTDYy93L7paiMPw\
     Pd4siSnaU3ajdQqNsgvSeqN5boFFDrTSxLgFQPFnv7Lghyfbx",
    "8C9Eo4cLy2DGjQBUhriTNNeAMWTNfPhSYNnsnFkCKJmB4xrYZ\
     UyK2N6irXBGB8iusv3fvvgpC6SgjNyXSTdSQp7t1VVMvqa",
  ] {
    let address = MoneroAddress::from_str(Network::Mainnet, encoded_address).unwrap();
    let secret = Zeroizing::new(Scalar::from(7u8));
    let public =
      if address.is_subaddress() { address.spend().into() } else { ED25519_BASEPOINT_POINT } *
        *secret;
    let mut extra = vec![1];
    extra.extend(public.compress().to_bytes());
    let shared = address.view().into() * *secret;
    let mut derivation = shared.mul_by_cofactor().compress().to_bytes().to_vec();
    derivation.push(0); // output index as a varint
    let scalar = Scalar::from_bytes_mod_order(keccak256(&derivation));
    let output_key = Point::from(address.spend().into() + (ED25519_BASEPOINT_POINT * scalar));
    let tx = Transaction::V1 {
      prefix: TransactionPrefix {
        additional_timelock: Timelock::None,
        inputs: vec![Input::Gen(1)],
        outputs: vec![Output { amount: Some(123), key: output_key.compress(), view_tag: None }],
        extra,
      },
      signatures: vec![],
    };
    let proof = OutProof::prove(&mut OsRng, &address, &secret, b"receipt");
    assert_eq!(proof.verify(&tx, 0, &address, b"receipt"), Some(123));
    assert_eq!(proof.verify(&tx, 1, &address, b"receipt"), None);
    assert_eq!(proof.verify(&tx, 0, &address, b"different"), None);

    let mask = Scalar::from_bytes_mod_order(keccak256(
      [b"commitment_mask".as_slice(), &scalar.to_bytes()].concat(),
    ));
    let amount_mask = keccak256([b"amount".as_slice(), &scalar.to_bytes()].concat());
    let amount = 123;
    let encrypted =
      (amount ^ u64::from_le_bytes(amount_mask[.. 8].try_into().unwrap())).to_le_bytes();
    let mut prefix = tx.prefix().clone();
    prefix.outputs[0].amount = None;
    let mut confidential = Transaction::V2 {
      prefix,
      proofs: Some(RctProofs {
        base: RctBase {
          fee: 1,
          pseudo_outs: vec![],
          encrypted_amounts: vec![EncryptedAmount::Compact { amount: encrypted }],
          commitments: vec![Commitment::new(OxideScalar::from(mask), 123).commit().compress()],
        },
        prunable: RctPrunable::MlsagBorromean { mlsags: vec![], borromean: vec![] },
      }),
    };
    assert_eq!(proof.verify(&confidential, 0, &address, b"receipt"), Some(123));
    if let Transaction::V2 { proofs: Some(proofs), .. } = &mut confidential {
      proofs.base.commitments[0] = CompressedPoint::G;
    }
    assert_eq!(proof.verify(&confidential, 0, &address, b"receipt"), None);
    let mut wrong = tx;
    wrong.prefix_mut().outputs[0].key = CompressedPoint::G;
    assert_eq!(proof.verify(&wrong, 0, &address, b"receipt"), None);
  }
}

#[test]
fn rejects_invalid_proof_encodings() {
  for invalid in ["", "garbage", "OutProofV1", "OutProofV2x", "OutProofV2💰"] {
    assert_eq!(OutProof::read(invalid), None);
  }
  assert_eq!(OutProof::read(&OutProof::serialize(&[])), Some(vec![]));
  let invalid_point =
    format!("OutProofV2{}{}", monero_base58::encode(&[255; 32]), monero_base58::encode(&[0; 64]));
  assert_eq!(OutProof::read(&invalid_point), None);
  let invalid_scalars = format!(
    "OutProofV2{}{}",
    monero_base58::encode(&CompressedPoint::G.to_bytes()),
    monero_base58::encode(&[255; 64])
  );
  assert_eq!(OutProof::read(&invalid_scalars), None);
}
