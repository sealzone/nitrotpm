//! A TPM that answers the commands of the attestation flow as the TPM 2.0 reference
//! implementation and NitroTPM do, parsed from the bytes: the tests check what goes on the
//! wire, not the client's own view of it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ciborium::Value;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha512};

use crate::{Error, Transport};

const NV_INDEX_FIRST: u32 = 0x0100_0000;
const SESSION_HANDLE: u32 = 0x0200_0000;

pub(crate) struct Index {
    pub public: Vec<u8>,
    pub auth: Vec<u8>,
    pub data: Vec<u8>,
    pub written: bool,
}

#[derive(Default)]
pub(crate) struct State {
    pub indices: BTreeMap<u32, Index>,
    /// Open sessions: handle → the TPM's latest nonce.
    pub sessions: BTreeMap<u32, Vec<u8>>,
    /// Indices some other process defined.
    pub taken: Vec<u32>,
    /// The largest index this TPM allows (NitroTPM on a t3 refuses 8 KiB).
    pub max_index: usize,
    pub nv_buffer_max: u32,
    /// What the NSM answers, given the request.
    pub nsm: Option<fn(&Value) -> Value>,
    /// Commands received, by code.
    pub log: Vec<u32>,
    /// The response code of the vendor command, instead of running it.
    pub vendor_rc: Option<u32>,
    /// Reports another index from `GetCapability` than the ones defined, once, so the
    /// first define collides.
    pub hide_taken: bool,
}

#[derive(Clone)]
pub(crate) struct FakeTpm(pub Arc<Mutex<State>>);

impl FakeTpm {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            max_index: 8192,
            nv_buffer_max: 1024,
            nsm: Some(document_from_request),
            ..Default::default()
        })))
    }
}

/// The NSM's answer: a "document" that is the CBOR of the request's fields.
pub(crate) fn document_from_request(request: &Value) -> Value {
    let mut doc = Vec::new();
    ciborium::into_writer(request, &mut doc).unwrap();
    Value::Map(vec![(
        Value::Text("Attestation".into()),
        Value::Map(vec![(Value::Text("document".into()), Value::Bytes(doc))]),
    )])
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().unwrap())
    }
    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }
    fn sized(&mut self) -> &'a [u8] {
        let n = self.u16() as usize;
        self.take(n)
    }
}

struct Session<'a> {
    handle: u32,
    nonce: &'a [u8],
    attributes: u8,
    hmac: &'a [u8],
}

fn response(tag: u16, rc: u32, handles: &[u32], params: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&rc.to_be_bytes());
    if rc == 0 {
        for h in handles {
            out.extend_from_slice(&h.to_be_bytes());
        }
        if tag == 0x8002 {
            out.extend_from_slice(&(params.len() as u32).to_be_bytes());
            out.extend_from_slice(params);
            // One response session: empty nonce, attributes, empty HMAC.
            out.extend_from_slice(&[0, 0, 0, 0, 0]);
        } else {
            out.extend_from_slice(params);
        }
    } else {
        out[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
    }
    let size = out.len() as u32;
    out[2..6].copy_from_slice(&size.to_be_bytes());
    out
}

fn sized(b: &[u8]) -> Vec<u8> {
    [&(b.len() as u16).to_be_bytes()[..], b].concat()
}

fn trim(auth: &[u8]) -> &[u8] {
    let end = auth.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    &auth[..end]
}

const RC_AUTH_FAIL: u32 = 0x98E;
const RC_HANDLE: u32 = 0x18B;
const RC_NV_DEFINED: u32 = 0x14C;
const RC_NV_UNINITIALIZED: u32 = 0x14A;
const RC_SIZE_P2: u32 = 0x2D5;

impl State {
    /// The index's public area as it is now: `TPMA_NV_WRITTEN` once written.
    fn public(&self, index: u32) -> Vec<u8> {
        let i = &self.indices[&index];
        let mut public = i.public.clone();
        if i.written {
            let attrs = u32::from_be_bytes(public[6..10].try_into().unwrap()) | 1 << 29;
            public[6..10].copy_from_slice(&attrs.to_be_bytes());
        }
        public
    }

    fn name(&self, index: u32) -> Vec<u8> {
        [
            &0x000Du16.to_be_bytes()[..],
            &Sha512::digest(self.public(index)),
        ]
        .concat()
    }

    fn password_ok(&self, s: &Session<'_>, auth: &[u8]) -> bool {
        s.handle == 0x4000_0009 && s.nonce.is_empty() && trim(s.hmac) == trim(auth)
    }

    fn run(&mut self, cmd: &[u8]) -> Vec<u8> {
        let mut r = Reader(cmd);
        let tag = r.u16();
        assert_eq!(r.u32() as usize, cmd.len(), "command size");
        let code = r.u32();
        self.log.push(code);
        let handles = match code {
            0x122 | 0x137 | 0x14E | 0x2000_0001 => 2,
            0x12A | 0x169 => 1,
            0x176 => 2,
            _ => 0,
        };
        let hs: Vec<u32> = (0..handles).map(|_| r.u32()).collect();
        let mut sessions = Vec::new();
        if tag == 0x8002 {
            let size = r.u32() as usize;
            let mut a = Reader(r.take(size));
            while !a.0.is_empty() {
                sessions.push(Session {
                    handle: a.u32(),
                    nonce: a.sized(),
                    attributes: a.u8(),
                    hmac: a.sized(),
                });
            }
        }
        let params = r.0;
        let mut p = Reader(params);
        let ok = |params: &[u8]| response(tag, 0, &[], params);
        let err = |rc| response(tag, rc, &[], &[]);
        match code {
            // GetCapability
            0x17A => {
                let (cap, prop, _count) = (p.u32(), p.u32(), p.u32());
                let mut out = vec![0u8];
                out.extend_from_slice(&cap.to_be_bytes());
                if cap == 6 {
                    assert_eq!(prop, 0x12C);
                    out.extend_from_slice(&1u32.to_be_bytes());
                    out.extend_from_slice(&0x12Cu32.to_be_bytes());
                    out.extend_from_slice(&self.nv_buffer_max.to_be_bytes());
                } else {
                    let mut listed: Vec<u32> = self
                        .indices
                        .keys()
                        .copied()
                        .filter(|i| *i >= prop)
                        .collect();
                    if !self.hide_taken {
                        listed.extend(self.taken.iter().filter(|i| **i >= prop));
                    }
                    self.hide_taken = false;
                    listed.sort();
                    out.extend_from_slice(&(listed.len() as u32).to_be_bytes());
                    for i in listed {
                        out.extend_from_slice(&i.to_be_bytes());
                    }
                }
                ok(&out)
            }
            // NV_DefineSpace
            0x12A => {
                assert_eq!(hs[0], 0x4000_0001, "owner authorizes");
                if !self.password_ok(&sessions[0], &[]) {
                    return err(RC_AUTH_FAIL);
                }
                let auth = p.sized().to_vec();
                let public = p.sized().to_vec();
                let mut pr = Reader(&public);
                let index = pr.u32();
                assert_eq!(pr.u16(), 0x000D, "SHA-512 name");
                let _attrs = pr.u32();
                assert!(pr.sized().is_empty(), "no policy");
                let size = pr.u16() as usize;
                if size > self.max_index {
                    return err(RC_SIZE_P2);
                }
                if self.indices.contains_key(&index) || self.taken.contains(&index) {
                    return err(RC_NV_DEFINED);
                }
                assert!(index >= NV_INDEX_FIRST);
                self.indices.insert(
                    index,
                    Index {
                        public,
                        auth: trim(&auth).to_vec(),
                        data: vec![0xFF; size],
                        written: false,
                    },
                );
                ok(&[])
            }
            // NV_UndefineSpace
            0x122 => {
                assert_eq!(hs[0], 0x4000_0001);
                if !self.password_ok(&sessions[0], &[]) {
                    return err(RC_AUTH_FAIL);
                }
                match self.indices.remove(&hs[1]) {
                    Some(_) => ok(&[]),
                    None => err(RC_HANDLE),
                }
            }
            // NV_Write
            0x137 => {
                let Some(i) = self.indices.get(&hs[1]) else {
                    return err(RC_HANDLE);
                };
                assert_eq!(hs[0], hs[1], "the index authorizes itself");
                if !self.password_ok(&sessions[0], &i.auth) {
                    return err(RC_AUTH_FAIL);
                }
                let data = p.sized().to_vec();
                let offset = p.u16() as usize;
                assert!(
                    data.len() <= self.nv_buffer_max as usize,
                    "write over NV_BUFFER_MAX"
                );
                let i = self.indices.get_mut(&hs[1]).unwrap();
                i.data[offset..offset + data.len()].copy_from_slice(&data);
                i.written = true;
                ok(&[])
            }
            // NV_Read
            0x14E => {
                let Some(i) = self.indices.get(&hs[1]) else {
                    return err(RC_HANDLE);
                };
                if !self.password_ok(&sessions[0], &i.auth) {
                    return err(RC_AUTH_FAIL);
                }
                if !i.written {
                    return err(RC_NV_UNINITIALIZED);
                }
                let (size, offset) = (p.u16() as usize, p.u16() as usize);
                assert!(
                    size <= self.nv_buffer_max as usize,
                    "read over NV_BUFFER_MAX"
                );
                ok(&sized(&i.data[offset..offset + size]))
            }
            // NV_ReadPublic
            0x169 => {
                if !self.indices.contains_key(&hs[0]) {
                    return err(RC_HANDLE);
                }
                ok(&[sized(&self.public(hs[0])), sized(&self.name(hs[0]))].concat())
            }
            // StartAuthSession
            0x176 => {
                assert_eq!(hs, [0x4000_0007, 0x4000_0007], "unbound, unsalted");
                let nonce_caller = p.sized();
                assert!(nonce_caller.len() >= 16);
                assert!(p.sized().is_empty(), "no salt");
                assert_eq!(p.u8(), 0x00, "HMAC session");
                assert_eq!(p.u16(), 0x0010, "no parameter encryption");
                assert_eq!(p.u16(), 0x000D, "SHA-512");
                let nonce_tpm: Vec<u8> = (0..64).map(|i| i as u8 ^ 0x5A).collect();
                let handle = SESSION_HANDLE + self.sessions.len() as u32;
                self.sessions.insert(handle, nonce_tpm.clone());
                response(tag, 0, &[handle], &sized(&nonce_tpm))
            }
            // FlushContext
            0x165 => match self.sessions.remove(&p.u32()) {
                Some(_) => ok(&[]),
                None => err(RC_HANDLE),
            },
            // The vendor command
            0x2000_0001 => {
                if let Some(rc) = self.vendor_rc {
                    return err(rc);
                }
                assert_eq!(hs[0], hs[1]);
                let Some(index) = self.indices.get(&hs[1]) else {
                    return err(RC_HANDLE);
                };
                let s = &sessions[0];
                let Some(nonce_tpm) = self.sessions.get(&s.handle) else {
                    return err(RC_HANDLE);
                };
                let name = self.name(hs[1]);
                let cp = Sha512::new()
                    .chain_update(code.to_be_bytes())
                    .chain_update(&name)
                    .chain_update(&name)
                    .finalize();
                let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&index.auth).unwrap();
                mac.update(&cp);
                mac.update(s.nonce);
                mac.update(nonce_tpm);
                mac.update(&[s.attributes]);
                if mac.verify_slice(s.hmac).is_err() {
                    return err(RC_AUTH_FAIL);
                }
                if s.attributes & 1 == 0 {
                    self.sessions.remove(&s.handle);
                }
                let request: Value = ciborium::from_reader(index.data.as_slice())
                    .expect("CBOR request in the index");
                let answer = (self.nsm.unwrap())(&request);
                let mut out = Vec::new();
                ciborium::into_writer(&answer, &mut out).unwrap();
                let i = self.indices.get_mut(&hs[1]).unwrap();
                i.data[..out.len()].copy_from_slice(&out);
                ok(&[])
            }
            other => panic!("unexpected command {other:#x}"),
        }
    }
}

impl Transport for FakeTpm {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.lock().unwrap().run(command))
    }
}
