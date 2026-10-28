//! Retrieve a signed attestation document from an EC2 instance's NitroTPM, in pure Rust.
//!
//! The API matches AWS's [`nitro-tpm-attest`](https://crates.io/crates/nitro-tpm-attest).
//! [`attestation_document`] takes the optional user data, nonce and public key (at most
//! 1024 bytes each) and returns the document, a COSE_Sign1 over CBOR signed by the Nitro
//! hypervisor. The device is `/dev/tpm0`, or the path in `TPM_DEVICE`. The crate talks to
//! the TPM directly instead of through `libtss2`, so it builds anywhere Rust does, static
//! musl binaries included.
//!
//! The document comes from AWS's vendor command (`0x20000001`), which runs an NSM request
//! held in an NV index and writes the response back into it:
//!
//! 1. `NV_DefineSpace` an 8 KiB index (owner authorization, which is empty on EC2) with a
//!    random 64-byte authorization value, and `NV_Write` the CBOR request into it.
//! 2. `StartAuthSession` an unbound, unsalted HMAC session (SHA-512), and send the vendor
//!    command on the index with it. The session needs no salt because the index's
//!    authorization is random.
//! 3. `NV_Read` the CBOR response, then `NV_UndefineSpace` the index and `FlushContext` the
//!    session, even when a step fails.
//!
//! Only the raw device takes the vendor command, not the kernel's resource manager
//! (`/dev/tpmrm0`). Only one process can hold the raw device, so opening it fails with
//! `EBUSY` while another (such as `tpm2-abrmd`) has it open. Not every instance type with
//! NitroTPM can attest. Where the TPM refuses an 8 KiB index, the error is
//! [`Error::Unsupported`].

#![forbid(unsafe_code)]

mod nsm;
mod session;
mod wire;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod tests;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use wire::{Command, Response};

/// Why an attestation document could not be retrieved.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The device does not exist. Either this is not an EC2 instance, or its AMI was not
    /// registered with `--tpm-support v2.0`.
    #[error("no TPM at {0}")]
    NoDevice(PathBuf),
    /// The device exists but this process may not open it (it is `root:root 0600` by default).
    #[error("no permission to open {0}")]
    PermissionDenied(PathBuf),
    /// Another process holds the raw device open.
    #[error("{0} is in use by another process")]
    Busy(PathBuf),
    /// The device is the kernel's resource manager (`/dev/tpmrm0`), which refuses AWS's
    /// vendor command.
    #[error("{0} is not the raw TPM device: the attestation command only goes through /dev/tpm0")]
    NotRawDevice(PathBuf),
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
    /// The TPM refused the 8 KiB message buffer. This instance type has NitroTPM but cannot
    /// attest.
    #[error("this TPM cannot hold the attestation buffer (TPM error {0:#x}); the instance type cannot attest")]
    Unsupported(u32),
    /// A user data, nonce or public key over 1024 bytes.
    #[error("{0} is longer than 1024 bytes")]
    TooLong(&'static str),
    #[error("TPM command {command:#x} failed with TPM error {code:#x}")]
    Tpm { command: u32, code: u32 },
    #[error("malformed TPM response to command {0:#x}")]
    InvalidTpmResponse(u32),
    #[error("invalid NSM response")]
    InvalidNsmResponse,
    /// The NSM's own error, such as `InvalidArgument`.
    #[error("NSM error response: {0}")]
    NsmErrorResponse(String),
    #[error("no free NV index")]
    NvIndexHandleCapacity,
    #[error("no randomness: {0}")]
    Random(String),
}

/// Request a NitroTPM attestation document, from `TPM_DEVICE` or `/dev/tpm0`.
pub fn attestation_document(
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    Tpm::open(device_path())?.attestation_document(
        user_data.as_deref(),
        nonce.as_deref(),
        public_key.as_deref(),
    )
}

/// `TPM_DEVICE`, or `/dev/tpm0`.
pub fn device_path() -> PathBuf {
    std::env::var_os("TPM_DEVICE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/dev/tpm0".into())
}

/// Something that runs one TPM command and returns its response.
trait Transport {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, Error>;
}

/// The raw TPM device, held open.
pub struct Tpm {
    path: PathBuf,
    transport: Box<dyn Transport>,
}

struct Device {
    path: PathBuf,
    file: std::fs::File,
}

impl Transport for Device {
    fn transact(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        let io = |e| Error::Io(self.path.clone(), e);
        self.file.write_all(command).map_err(io)?;
        // The kernel returns the whole response in one read.
        let mut response = vec![0u8; 16 * 1024];
        let n = self.file.read(&mut response).map_err(io)?;
        response.truncate(n);
        Ok(response)
    }
}

/// The NV index buffer: the plain document is almost 5 KiB, and each optional field adds at
/// most 1 KiB.
const BUFFER_SIZE: u16 = 8192;

const MAX_FIELD: usize = 1024;

impl Tpm {
    /// Opens the raw device at `path` for reading and writing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Error::NoDevice(path.clone()),
                std::io::ErrorKind::PermissionDenied => Error::PermissionDenied(path.clone()),
                std::io::ErrorKind::ResourceBusy => Error::Busy(path.clone()),
                _ => Error::Io(path.clone(), e),
            })?;
        Ok(Self {
            path: path.clone(),
            transport: Box::new(Device { path, file }),
        })
    }

    #[cfg(test)]
    fn with_transport(transport: impl Transport + 'static) -> Self {
        Self {
            path: "/dev/fake-tpm".into(),
            transport: Box::new(transport),
        }
    }

    /// Request an attestation document over this device.
    pub fn attestation_document(
        &mut self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        for (name, field) in [
            ("user_data", user_data),
            ("nonce", nonce),
            ("public_key", public_key),
        ] {
            if field.is_some_and(|f| f.len() > MAX_FIELD) {
                return Err(Error::TooLong(name));
            }
        }
        let request = nsm::attestation_request(user_data, nonce, public_key);

        let auth = session::auth_value()?;
        let index = self.define_index(&auth)?;
        let result = self.run(index, &auth, &request);
        let undefined = self.undefine_index(index);
        let response = result?;
        undefined?;
        nsm::attestation_response(&response)
    }

    /// Writes the request into the defined index, sends the vendor command and reads the
    /// response back; the caller undefines the index.
    fn run(&mut self, index: u32, auth: &[u8], request: &[u8]) -> Result<Vec<u8>, Error> {
        let chunk = self.nv_buffer_max()?;
        for (i, part) in request.chunks(chunk).enumerate() {
            self.nv_write(index, auth, part, (i * chunk) as u16)?;
        }
        let name = self.nv_name(index)?;
        let (handle, nonce_tpm) = self.start_session()?;
        let sent = self.nsm_request(index, auth, &name, handle, &nonce_tpm);
        let flushed = self.flush(handle);
        sent?;
        flushed?;
        let mut response = Vec::with_capacity(BUFFER_SIZE as usize);
        while response.len() < BUFFER_SIZE as usize {
            let size = chunk.min(BUFFER_SIZE as usize - response.len());
            response.extend_from_slice(&self.nv_read(
                index,
                auth,
                size as u16,
                response.len() as u16,
            )?);
        }
        Ok(response)
    }

    fn call<T>(
        &mut self,
        command: Vec<u8>,
        code: u32,
        handles: usize,
        f: impl FnOnce(Response<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let bytes = self.transport.transact(&command)?;
        f(Response::parse(&bytes, code, handles)?)
    }

    /// The largest `NV_Write` or `NV_Read` the TPM takes.
    fn nv_buffer_max(&mut self) -> Result<usize, Error> {
        let code = wire::CC_GET_CAPABILITY;
        let command = Command::new(wire::ST_NO_SESSIONS, code)
            .u32(wire::CAP_TPM_PROPERTIES)
            .u32(wire::PT_NV_BUFFER_MAX)
            .u32(1)
            .build();
        self.call(command, code, 0, |mut r| {
            let _more = r.u8()?;
            if r.u32()? != wire::CAP_TPM_PROPERTIES
                || r.u32()? != 1
                || r.u32()? != wire::PT_NV_BUFFER_MAX
            {
                return Err(Error::InvalidTpmResponse(code));
            }
            match r.u32()? {
                0 => Err(Error::InvalidTpmResponse(code)),
                max => Ok(max as usize),
            }
        })
    }

    /// The NV indices in use.
    fn nv_indices(&mut self) -> Result<Vec<u32>, Error> {
        let code = wire::CC_GET_CAPABILITY;
        let mut all = Vec::new();
        let mut from = wire::NV_INDEX_FIRST;
        loop {
            let command = Command::new(wire::ST_NO_SESSIONS, code)
                .u32(wire::CAP_HANDLES)
                .u32(from)
                .u32(wire::NV_INDEX_LAST - from + 1)
                .build();
            let more = self.call(command, code, 0, |mut r| {
                let more = r.u8()? != 0;
                if r.u32()? != wire::CAP_HANDLES {
                    return Err(Error::InvalidTpmResponse(code));
                }
                for _ in 0..r.u32()? {
                    all.push(r.u32()?);
                }
                Ok(more)
            })?;
            match all.last() {
                Some(&last) if more && last < wire::NV_INDEX_LAST => from = last + 1,
                _ => return Ok(all),
            }
        }
    }

    /// Defines the message buffer at the first free index, with `auth`.
    fn define_index(&mut self, auth: &[u8]) -> Result<u32, Error> {
        let used = self.nv_indices()?;
        let mut candidates =
            (wire::NV_INDEX_FIRST..=wire::NV_INDEX_LAST).filter(|i| !used.contains(i));
        loop {
            let index = candidates.next().ok_or(Error::NvIndexHandleCapacity)?;
            let code = wire::CC_NV_DEFINE_SPACE;
            let command = Command::new(wire::ST_SESSIONS, code)
                .u32(wire::RH_OWNER)
                .auth(&wire::password(&[]))
                .sized(auth)
                .sized(&nv_public(index, false))
                .build();
            match self.call(command, code, 0, |_| Ok(())) {
                Ok(()) => return Ok(index),
                // Taken since it was listed.
                Err(Error::Tpm {
                    code: wire::RC_NV_DEFINED,
                    ..
                }) => continue,
                // TPM_RC_SIZE (or another size or value error on the public area): the index is
                // larger than this TPM allows.
                Err(Error::Tpm { code: rc, .. }) if is_size_error(rc) => {
                    return Err(Error::Unsupported(rc))
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn undefine_index(&mut self, index: u32) -> Result<(), Error> {
        let code = wire::CC_NV_UNDEFINE_SPACE;
        let command = Command::new(wire::ST_SESSIONS, code)
            .u32(wire::RH_OWNER)
            .u32(index)
            .auth(&wire::password(&[]))
            .build();
        self.call(command, code, 0, |_| Ok(()))
    }

    fn nv_write(&mut self, index: u32, auth: &[u8], data: &[u8], offset: u16) -> Result<(), Error> {
        let code = wire::CC_NV_WRITE;
        let command = Command::new(wire::ST_SESSIONS, code)
            .u32(index)
            .u32(index)
            .auth(&wire::password(auth))
            .sized(data)
            .u16(offset)
            .build();
        self.call(command, code, 0, |_| Ok(()))
    }

    fn nv_read(
        &mut self,
        index: u32,
        auth: &[u8],
        size: u16,
        offset: u16,
    ) -> Result<Vec<u8>, Error> {
        let code = wire::CC_NV_READ;
        let command = Command::new(wire::ST_SESSIONS, code)
            .u32(index)
            .u32(index)
            .auth(&wire::password(auth))
            .u16(size)
            .u16(offset)
            .build();
        let data = self.call(command, code, 0, |mut r| Ok(r.sized()?.to_vec()))?;
        if data.len() != size as usize {
            return Err(Error::InvalidTpmResponse(code));
        }
        Ok(data)
    }

    /// The index's name as the TPM computes it now (written, so with `TPMA_NV_WRITTEN`).
    fn nv_name(&mut self, index: u32) -> Result<Vec<u8>, Error> {
        let code = wire::CC_NV_READ_PUBLIC;
        let command = Command::new(wire::ST_NO_SESSIONS, code).u32(index).build();
        self.call(command, code, 0, |mut r| {
            let public = r.sized()?;
            let name = r.sized()?;
            // The TPM's description must be the one defined, written.
            if public != nv_public(index, true) {
                return Err(Error::InvalidTpmResponse(code));
            }
            Ok(name.to_vec())
        })
    }

    fn start_session(&mut self) -> Result<(u32, Vec<u8>), Error> {
        let code = wire::CC_START_AUTH_SESSION;
        let nonce_caller = session::nonce()?;
        let command = Command::new(wire::ST_NO_SESSIONS, code)
            .u32(wire::RH_NULL)
            .u32(wire::RH_NULL)
            .sized(&nonce_caller)
            .sized(&[])
            .u8(wire::SE_HMAC)
            .u16(wire::ALG_NULL)
            .u16(wire::ALG_SHA512)
            .build();
        self.call(command, code, 1, |mut r| {
            Ok((r.handles[0], r.sized()?.to_vec()))
        })
    }

    fn nsm_request(
        &mut self,
        index: u32,
        auth: &[u8],
        name: &[u8],
        handle: u32,
        nonce_tpm: &[u8],
    ) -> Result<(), Error> {
        let code = wire::CC_VENDOR_AWS_NSM_REQUEST;
        let nonce_caller = session::nonce()?;
        // The authorization handle and the index are both the index.
        let cp_hash = session::cp_hash(code, &[name, name], &[]);
        let hmac = session::command_hmac(
            auth,
            &cp_hash,
            &nonce_caller,
            nonce_tpm,
            wire::SESSION_CONTINUE,
        );
        let command = Command::new(wire::ST_SESSIONS, code)
            .u32(index)
            .u32(index)
            .auth(&wire::session(
                handle,
                &nonce_caller,
                wire::SESSION_CONTINUE,
                &hmac,
            ))
            .build();
        match self.call(command, code, 0, |_| Ok(())) {
            // A resource manager's TPM_RC_COMMAND_CODE: it passes on only the commands it knows.
            Err(Error::Tpm { code: rc, .. }) if rc == RM_COMMAND_CODE => {
                Err(Error::NotRawDevice(self.path.clone()))
            }
            r => r,
        }
    }

    fn flush(&mut self, handle: u32) -> Result<(), Error> {
        let code = wire::CC_FLUSH_CONTEXT;
        let command = Command::new(wire::ST_NO_SESSIONS, code).u32(handle).build();
        self.call(command, code, 0, |_| Ok(()))
    }
}

/// `TPMS_NV_PUBLIC` of the message buffer: SHA-512 name, `AUTHREAD | AUTHWRITE`, no policy.
fn nv_public(index: u32, written: bool) -> Vec<u8> {
    let attributes =
        wire::NVA_AUTHREAD | wire::NVA_AUTHWRITE | if written { wire::NVA_WRITTEN } else { 0 };
    let mut p = Vec::with_capacity(14);
    p.extend_from_slice(&index.to_be_bytes());
    p.extend_from_slice(&wire::ALG_SHA512.to_be_bytes());
    p.extend_from_slice(&attributes.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&BUFFER_SIZE.to_be_bytes());
    p
}

/// `TPM_RC_COMMAND_CODE` from the resource manager layer (`TSS2_RESMGR_TPM_RC_LAYER`), as
/// the kernel's `/dev/tpmrm0` answers a command it does not know.
const RM_COMMAND_CODE: u32 = 0x000B_0143;

/// `TPM_RC_SIZE` or `TPM_RC_VALUE`, in either response-code format: a format-one code
/// (bit 7) carries the parameter number in bits 8..11, so compare the error number only.
fn is_size_error(rc: u32) -> bool {
    const RC_VALUE: u32 = 0x084;
    const RC_SIZE: u32 = 0x095;
    rc & 0x080 != 0 && matches!(rc & 0x0BF, RC_VALUE | RC_SIZE)
}
