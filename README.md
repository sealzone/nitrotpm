# nitrotpm

Retrieve a signed attestation document from an EC2 instance's NitroTPM, in pure Rust.

It has the API and CLI of AWS's [`nitro-tpm-attest`](https://crates.io/crates/nitro-tpm-attest), but talks to the TPM directly instead of through `libtss2`. So it builds anywhere Rust does: static musl binaries, Python and Node extensions, and cross-compiled builds, with no C toolchain or system libraries.

```rust
let document = nitrotpm::attestation_document(
    Some(b"user data".to_vec()), // user_data, at most 1024 bytes
    Some(nonce.to_vec()),        // nonce, at most 1024 bytes
    None,                        // public_key, DER, at most 1024 bytes
)?;
```

The document is a COSE_Sign1 over CBOR, signed by the Nitro hypervisor through the [AWS Nitro attestation PKI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation-document-validate.html). It holds the instance's PCRs, your user data, nonce and public key, and a `module_id` that names the instance (`i-…-tpm…`). Verifying it is up to you: this crate only retrieves it.

The CLI writes the document to stdout:

```
nitrotpm --nonce nonce.bin --user-data data.bin > document.cbor
```

## Requirements

- **NitroTPM turned on.** The AMI must be registered with `--tpm-support v2.0 --boot-mode uefi`. AWS doesn't publish Linux AMIs with it on, so you register your own. See [Requirements for using NitroTPM](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html).
- **An instance type that can attest.** Some types have NitroTPM but refuse the 8 KiB buffer that attestation needs. A t3 does, and a c7i doesn't. That refusal is `Error::Unsupported`.
- **The raw device.** The document comes from AWS's vendor command, which goes only through `/dev/tpm0`, not the kernel's resource manager `/dev/tpmrm0`. Set `TPM_DEVICE` to use another path.
  - On Amazon Linux 2023 the device is `root:root 0600`. Run as root, or hand the device to a group with a udev rule (`KERNEL=="tpm0", GROUP="tss", MODE="0660"`).
  - The raw device is exclusive: while another process (such as `tpm2-abrmd`) holds it, opening it fails with `Error::Busy`.

## How it works

TPM 2.0 commands, marshaled by hand:

1. `NV_DefineSpace` an 8 KiB NV index under the owner hierarchy, with a random 64-byte authorization value. The owner authorization is empty on EC2.
2. `NV_Write` the NSM request into the index, in chunks of the TPM's `TPM_PT_NV_BUFFER_MAX`. The request is the same CBOR that `aws-nitro-enclaves-nsm-api` writes.
3. `StartAuthSession` an HMAC session (SHA-512). It needs no salt, because the index's authorization is random.
4. Send vendor command `0x20000001` on the index, authorized by that session. The hypervisor replaces the request with its response.
5. `NV_Read` the response, then `NV_UndefineSpace` the index and `FlushContext` the session. Cleanup runs even when a step failed.

### Differences from `nitro-tpm-attest`

- **No endorsement key.** AWS's tool creates and persists an endorsement key to salt its sessions. This crate uses an unsalted session instead, so it writes nothing persistent to the TPM, and it doesn't leave an endorsement key behind if it crashes.
- **No trailing zeros in the authorization value.** The TPM strips trailing zero bytes from an authorization value. A random one that ends in zero would then fail to authorize. This crate never makes one.
- **Errors you can act on.** `NoDevice`, `PermissionDenied`, `Busy`, `NotRawDevice` and `Unsupported` each say what to fix.

## License

Apache-2.0.
