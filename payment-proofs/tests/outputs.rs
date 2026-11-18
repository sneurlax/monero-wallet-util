//! OutProof::verify against synthetic transactions.

use monero_payment_proofs::OutProof;
use monero_wallet::ed25519::CompressedPoint;

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
