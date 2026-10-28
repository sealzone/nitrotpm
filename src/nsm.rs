//! The NSM request and response, in the CBOR that `aws-nitro-enclaves-nsm-api` writes:
//! `{"Attestation": {"user_data": .., "nonce": .., "public_key": ..}}` with each field a byte
//! string or null, answered by `{"Attestation": {"document": ..}}` or `{"Error": "<code>"}`.

use ciborium::Value;

use crate::Error;

pub(crate) fn attestation_request(
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Vec<u8> {
    let field = |v: Option<&[u8]>| v.map_or(Value::Null, |b| Value::Bytes(b.to_vec()));
    let request = Value::Map(vec![(
        Value::Text("Attestation".into()),
        Value::Map(vec![
            (Value::Text("user_data".into()), field(user_data)),
            (Value::Text("nonce".into()), field(nonce)),
            (Value::Text("public_key".into()), field(public_key)),
        ]),
    )]);
    let mut out = Vec::new();
    ciborium::into_writer(&request, &mut out).expect("writing to a Vec cannot fail");
    out
}

/// The document in a response read from the buffer (the CBOR value, then the buffer's
/// unused rest).
pub(crate) fn attestation_response(buffer: &[u8]) -> Result<Vec<u8>, Error> {
    let value: Value = ciborium::from_reader(buffer).map_err(|_| Error::InvalidNsmResponse)?;
    let Value::Map(mut entries) = value else {
        return Err(Error::InvalidNsmResponse);
    };
    if entries.len() != 1 {
        return Err(Error::InvalidNsmResponse);
    }
    match entries.remove(0) {
        (Value::Text(k), Value::Map(fields)) if k == "Attestation" => fields
            .into_iter()
            .find_map(|(k, v)| match (k, v) {
                (Value::Text(k), Value::Bytes(doc)) if k == "document" => Some(doc),
                _ => None,
            })
            .ok_or(Error::InvalidNsmResponse),
        (Value::Text(k), Value::Text(code)) if k == "Error" => Err(Error::NsmErrorResponse(code)),
        _ => Err(Error::InvalidNsmResponse),
    }
}
