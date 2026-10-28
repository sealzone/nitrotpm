//! On a NitroTPM instance that can attest, as root: `cargo test -- --ignored`.

#[test]
#[ignore = "needs an EC2 instance with NitroTPM"]
fn real_document() {
    let nonce = b"nitrotpm hardware test".to_vec();
    let document =
        nitrotpm::attestation_document(Some(b"user data".to_vec()), Some(nonce.clone()), None)
            .unwrap();
    // A COSE_Sign1: a four-element array, whose payload names the nonce.
    assert_eq!(document[0], 0x84);
    assert!(document.windows(nonce.len()).any(|w| w == nonce.as_slice()));
}
