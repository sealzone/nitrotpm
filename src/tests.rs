//! The whole flow against `fake::FakeTpm`.

use ciborium::Value;

use crate::fake::{FakeTpm, State};
use crate::{nsm, session, Error, Tpm};

fn run(
    tpm: &FakeTpm,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    Tpm::with_transport(tpm.clone()).attestation_document(user_data, nonce, public_key)
}

fn state(tpm: &FakeTpm) -> std::sync::MutexGuard<'_, State> {
    tpm.0.lock().unwrap()
}

/// What the fake NSM saw, from the "document" it returns.
fn request_of(doc: &[u8]) -> Value {
    ciborium::from_reader(doc).unwrap()
}

#[track_caller]
fn assert_clean(tpm: &FakeTpm) {
    let s = state(tpm);
    assert!(s.indices.is_empty(), "an index is left defined");
    assert!(s.sessions.is_empty(), "a session is left open");
}

#[test]
fn document_carries_the_request() {
    let tpm = FakeTpm::new();
    let doc = run(&tpm, Some(b"ud"), Some(&[7; 32]), None).unwrap();
    assert_eq!(
        request_of(&doc),
        Value::Map(vec![(
            Value::Text("Attestation".into()),
            Value::Map(vec![
                (
                    Value::Text("user_data".into()),
                    Value::Bytes(b"ud".to_vec())
                ),
                (Value::Text("nonce".into()), Value::Bytes(vec![7; 32])),
                (Value::Text("public_key".into()), Value::Null),
            ]),
        )])
    );
    assert_clean(&tpm);
}

#[test]
fn request_matches_nsm_api_encoding() {
    // `aws_nitro_enclaves_nsm_api::api::Request::Attestation { user_data: None, nonce:
    // Some(b"n"), public_key: None }` through `ciborium::into_writer`.
    let expected: &[u8] = &[
        0xA1, 0x6B, b'A', b't', b't', b'e', b's', b't', b'a', b't', b'i', b'o', b'n', 0xA3, 0x69,
        b'u', b's', b'e', b'r', b'_', b'd', b'a', b't', b'a', 0xF6, 0x65, b'n', b'o', b'n', b'c',
        b'e', 0x41, b'n', 0x6A, b'p', b'u', b'b', b'l', b'i', b'c', b'_', b'k', b'e', b'y', 0xF6,
    ];
    assert_eq!(nsm::attestation_request(None, Some(b"n"), None), expected);
}

#[test]
fn largest_request_spans_several_writes_and_reads() {
    let tpm = FakeTpm::new();
    state(&tpm).nv_buffer_max = 512;
    let max = vec![9u8; 1024];
    let doc = run(&tpm, Some(&max), Some(&max), Some(&max)).unwrap();
    let Value::Map(outer) = request_of(&doc) else {
        panic!()
    };
    let Value::Map(fields) = &outer[0].1 else {
        panic!()
    };
    assert!(fields.iter().all(|(_, v)| *v == Value::Bytes(max.clone())));
    let log = state(&tpm).log.clone();
    assert!(
        log.iter().filter(|c| **c == 0x137).count() >= 7,
        "a 3 KiB request in 512-byte writes"
    );
    assert_eq!(
        log.iter().filter(|c| **c == 0x14E).count(),
        16,
        "8 KiB read in 512-byte reads"
    );
    assert_clean(&tpm);
}

#[test]
fn fields_over_1024_bytes_refused_before_the_tpm() {
    let tpm = FakeTpm::new();
    let r = run(&tpm, None, Some(&[0; 1025]), None);
    assert!(matches!(r, Err(Error::TooLong("nonce"))), "{r:?}");
    assert!(state(&tpm).log.is_empty());
}

#[test]
fn small_tpm_is_unsupported() {
    let tpm = FakeTpm::new();
    state(&tpm).max_index = 2048;
    let r = run(&tpm, None, Some(b"n"), None);
    assert!(matches!(r, Err(Error::Unsupported(0x2D5))), "{r:?}");
    assert_clean(&tpm);
}

#[test]
fn skips_indices_in_use() {
    let tpm = FakeTpm::new();
    state(&tpm).taken = vec![0x0100_0000, 0x0100_0001];
    run(&tpm, None, Some(b"n"), None).unwrap();
    // Another process took the first free index after it was listed.
    state(&tpm).taken = vec![0x0100_0000];
    state(&tpm).hide_taken = true;
    run(&tpm, None, Some(b"n"), None).unwrap();
    let s = state(&tpm);
    assert_eq!(s.taken, [0x0100_0000]);
    assert!(s.indices.is_empty());
}

#[test]
fn nsm_error_is_returned_and_cleaned_up() {
    let tpm = FakeTpm::new();
    state(&tpm).nsm = Some(|_| {
        Value::Map(vec![(
            Value::Text("Error".into()),
            Value::Text("InvalidArgument".into()),
        )])
    });
    let r = run(&tpm, None, Some(b"n"), None);
    assert!(
        matches!(&r, Err(Error::NsmErrorResponse(c)) if c == "InvalidArgument"),
        "{r:?}"
    );
    assert_clean(&tpm);
}

#[test]
fn failed_vendor_command_still_cleans_up() {
    let tpm = FakeTpm::new();
    state(&tpm).vendor_rc = Some(0x98E);
    let r = run(&tpm, None, Some(b"n"), None);
    assert!(
        matches!(
            r,
            Err(Error::Tpm {
                command: 0x2000_0001,
                code: 0x98E
            })
        ),
        "{r:?}"
    );
    assert_clean(&tpm);
}

#[test]
fn auth_value_has_no_trailing_zero() {
    for _ in 0..512 {
        assert_ne!(*session::auth_value().unwrap().last().unwrap(), 0);
    }
}

#[test]
fn size_errors() {
    assert!(crate::is_size_error(0x2D5)); // TPM_RC_SIZE, parameter 2
    assert!(crate::is_size_error(0x1C4)); // TPM_RC_VALUE, parameter 1
    assert!(!crate::is_size_error(0x98E)); // TPM_RC_AUTH_FAIL, session 1
    assert!(!crate::is_size_error(0x14C)); // TPM_RC_NV_DEFINED
}

#[test]
fn missing_device_is_named() {
    let r = Tpm::open("/nonexistent/tpm0");
    assert!(matches!(r, Err(Error::NoDevice(_))));
}

#[test]
fn resource_manager_is_named() {
    let tpm = FakeTpm::new();
    state(&tpm).vendor_rc = Some(0x000B_0143);
    let r = run(&tpm, None, Some(b"n"), None);
    assert!(matches!(r, Err(Error::NotRawDevice(_))), "{r:?}");
    assert_clean(&tpm);
}
