//! The HMAC session that authorizes the vendor command (TPM 2.0 Part 1 §19.6). The session
//! is unbound and unsalted, so its session key is empty and the HMAC key is the index's
//! authorization value alone.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha512};

use crate::Error;

/// The size of a SHA-512 digest: the nonce and authorization value size for a SHA-512
/// session and index.
const DIGEST_LEN: usize = 64;

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| Error::Random(e.to_string()))?;
    Ok(b)
}

pub(crate) fn nonce() -> Result<[u8; DIGEST_LEN], Error> {
    random()
}

/// A random authorization value whose last byte is not zero: the TPM strips trailing zeros
/// from an authorization value before it keys an HMAC with it.
pub(crate) fn auth_value() -> Result<[u8; DIGEST_LEN], Error> {
    let mut auth = random::<DIGEST_LEN>()?;
    auth[DIGEST_LEN - 1] |= 1;
    Ok(auth)
}

/// `cpHash = SHA-512(commandCode || names || parameters)` (Part 1 §18.7).
pub(crate) fn cp_hash(code: u32, names: &[&[u8]], parameters: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha512::new();
    h.update(code.to_be_bytes());
    for name in names {
        h.update(name);
    }
    h.update(parameters);
    h.finalize().into()
}

/// `HMAC(sessionKey || authValue, cpHash || nonceCaller || nonceTPM || sessionAttributes)`,
/// with an empty session key (Part 1 §19.6.5).
pub(crate) fn command_hmac(
    auth: &[u8],
    cp_hash: &[u8],
    nonce_caller: &[u8],
    nonce_tpm: &[u8],
    attributes: u8,
) -> [u8; DIGEST_LEN] {
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(auth).expect("HMAC takes any key");
    mac.update(cp_hash);
    mac.update(nonce_caller);
    mac.update(nonce_tpm);
    mac.update(&[attributes]);
    mac.finalize().into_bytes().into()
}
