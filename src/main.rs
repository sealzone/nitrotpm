//! `nitrotpm`: the attestation document on stdout, with the flags of AWS's `nitro-tpm-attest`.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "Request a TPM attestation document from NitroTPM

Usage: nitrotpm [OPTIONS]

Options:
  -u, --user-data <USER_DATA>    Path of user data to optional include
  -n, --nonce <NONCE>            Path of a nonce to optional include
  -p, --public-key <PUBLIC_KEY>  Path of a public key to optional include
  -h, --help                     Print help
  -V, --version                  Print version

The device is /dev/tpm0, or TPM_DEVICE.";

#[derive(Default)]
struct Arguments {
    user_data: Option<PathBuf>,
    nonce: Option<PathBuf>,
    public_key: Option<PathBuf>,
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Option<Arguments>, String> {
    let mut parsed = Arguments::default();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_owned(), Some(v.to_owned())),
            _ => (arg, None),
        };
        let slot = match flag.as_str() {
            "-u" | "--user-data" => &mut parsed.user_data,
            "-n" | "--nonce" => &mut parsed.nonce,
            "-p" | "--public-key" => &mut parsed.public_key,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("nitrotpm {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            other => return Err(format!("unexpected argument '{other}'\n\n{USAGE}")),
        };
        let value = inline
            .or_else(|| args.next())
            .ok_or_else(|| format!("{flag} needs a path"))?;
        if slot.replace(value.into()).is_some() {
            return Err(format!("{flag} given twice"));
        }
    }
    Ok(Some(parsed))
}

fn run() -> Result<(), String> {
    let Some(args) = parse(std::env::args().skip(1))? else {
        return Ok(());
    };
    let read = |p: Option<PathBuf>| {
        p.map(|p| std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display())))
            .transpose()
    };
    let document = nitrotpm::attestation_document(
        read(args.user_data)?,
        read(args.nonce)?,
        read(args.public_key)?,
    )
    .map_err(|e| e.to_string())?;
    std::io::stdout()
        .write_all(&document)
        .map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}
