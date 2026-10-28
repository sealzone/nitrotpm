//! TPM 2.0 command and response marshaling (TPM 2.0 Part 1 §18, Part 2), only as much as the
//! attestation flow needs. Everything is big-endian.

use crate::Error;

pub(crate) const ST_NO_SESSIONS: u16 = 0x8001;
pub(crate) const ST_SESSIONS: u16 = 0x8002;

pub(crate) const CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
pub(crate) const CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
pub(crate) const CC_NV_WRITE: u32 = 0x0000_0137;
pub(crate) const CC_NV_READ: u32 = 0x0000_014E;
pub(crate) const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub(crate) const CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
pub(crate) const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
pub(crate) const CC_GET_CAPABILITY: u32 = 0x0000_017A;
/// AWS's vendor command: run the NSM request held in an NV index, and write the response
/// back into it.
pub(crate) const CC_VENDOR_AWS_NSM_REQUEST: u32 = 0x2000_0001;

pub(crate) const RH_OWNER: u32 = 0x4000_0001;
pub(crate) const RH_NULL: u32 = 0x4000_0007;
pub(crate) const RS_PW: u32 = 0x4000_0009;

pub(crate) const CAP_HANDLES: u32 = 0x0000_0001;
pub(crate) const CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
pub(crate) const PT_NV_BUFFER_MAX: u32 = 0x0000_012C;

pub(crate) const ALG_SHA512: u16 = 0x000D;
pub(crate) const ALG_NULL: u16 = 0x0010;
pub(crate) const SE_HMAC: u8 = 0x00;

pub(crate) const NV_INDEX_FIRST: u32 = 0x0100_0000;
pub(crate) const NV_INDEX_LAST: u32 = 0x01FF_FFFF;
pub(crate) const NVA_AUTHWRITE: u32 = 1 << 2;
pub(crate) const NVA_AUTHREAD: u32 = 1 << 18;
pub(crate) const NVA_WRITTEN: u32 = 1 << 29;

pub(crate) const SESSION_CONTINUE: u8 = 0x01;

/// `TPM_RC_NV_DEFINED`: the index exists already.
pub(crate) const RC_NV_DEFINED: u32 = 0x0000_014C;

/// A command being built: header, then handles, then (with sessions) the authorization
/// area, then parameters.
pub(crate) struct Command {
    buf: Vec<u8>,
}

impl Command {
    pub fn new(tag: u16, code: u32) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&tag.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&code.to_be_bytes());
        Self { buf }
    }
    pub fn u8(mut self, v: u8) -> Self {
        self.buf.push(v);
        self
    }
    pub fn u16(mut self, v: u16) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(mut self, v: u32) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// A `TPM2B`: a u16 size, then the bytes.
    pub fn sized(mut self, data: &[u8]) -> Self {
        self = self.u16(data.len() as u16);
        self.buf.extend_from_slice(data);
        self
    }
    /// The authorization area: a u32 size, then the sessions.
    pub fn auth(mut self, sessions: &[u8]) -> Self {
        self = self.u32(sessions.len() as u32);
        self.buf.extend_from_slice(sessions);
        self
    }
    pub fn build(mut self) -> Vec<u8> {
        let size = self.buf.len() as u32;
        self.buf[2..6].copy_from_slice(&size.to_be_bytes());
        self.buf
    }
}

/// One session in an authorization area.
pub(crate) fn session(handle: u32, nonce: &[u8], attributes: u8, hmac: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(9 + nonce.len() + hmac.len());
    s.extend_from_slice(&handle.to_be_bytes());
    s.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    s.extend_from_slice(nonce);
    s.push(attributes);
    s.extend_from_slice(&(hmac.len() as u16).to_be_bytes());
    s.extend_from_slice(hmac);
    s
}

/// A password session carrying `password` (empty for an authorization that has none).
pub(crate) fn password(password: &[u8]) -> Vec<u8> {
    session(RS_PW, &[], 0, password)
}

/// A response: its handles, then its parameters (without the parameter size or the
/// authorization area that a response with sessions has around them).
pub(crate) struct Response<'a> {
    command: u32,
    pub handles: Vec<u32>,
    rest: &'a [u8],
}

impl<'a> Response<'a> {
    /// Checks the header of `bytes`, a response to `command` that returns `handles` handles.
    pub fn parse(bytes: &'a [u8], command: u32, handles: usize) -> Result<Self, Error> {
        let bad = || Error::InvalidTpmResponse(command);
        let header = bytes.get(..10).ok_or_else(bad)?;
        let tag = u16::from_be_bytes([header[0], header[1]]);
        let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let code = u32::from_be_bytes([header[6], header[7], header[8], header[9]]);
        if size != bytes.len() {
            return Err(bad());
        }
        if code != 0 {
            return Err(Error::Tpm { command, code });
        }
        let mut r = Self {
            command,
            handles: Vec::new(),
            rest: &bytes[10..],
        };
        for _ in 0..handles {
            let h = r.u32()?;
            r.handles.push(h);
        }
        match tag {
            ST_NO_SESSIONS => {}
            ST_SESSIONS => {
                let params = r.u32()? as usize;
                r.rest = r.rest.get(..params).ok_or_else(bad)?;
            }
            _ => return Err(bad()),
        }
        Ok(r)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.rest.len() < n {
            return Err(Error::InvalidTpmResponse(self.command));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn sized(&mut self) -> Result<&'a [u8], Error> {
        let b = self.take(2)?;
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        self.take(n)
    }
}
