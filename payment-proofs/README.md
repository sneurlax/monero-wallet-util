# Monero Payment Proofs

Create and verify Monero OutProofV2 payment proofs. `OutProof::verify` doesn't check
that the transaction is valid, confirmed, or unlocked. `OutProof::verify_signature`
checks only the signature, not outputs or amounts.
