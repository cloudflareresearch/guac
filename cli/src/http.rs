//! HTTP through the system curl. `guac::http` parses MOLE header fields.
//!
//! Every request, internal or `guac curl`, runs `curl -q` (no `.curlrc`).
//! Secret headers travel in private header files, never in process arguments.

use std::{
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use guac::http::{Challenge, CredentialField};
use serde::{Deserialize, Serialize};
use url::Url;

/// Internal protocol responses are small; larger bodies are rejected.
const MAX_INTERNAL_BODY: u64 = 1024 * 1024;

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Canonical unpadded base64url only, so values compare as strings.
pub fn decode(value: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    (encode(&bytes) == value).then_some(bytes)
}

pub fn random(length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; length];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
    Ok(bytes)
}

/// HTTPS, or HTTP to a loopback host for local development.
pub fn check_url(url: &Url) -> Result<()> {
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if url.scheme() == "https" || url.scheme() == "http" && loopback {
        Ok(())
    } else {
        bail!("{url} must use https (http is allowed only for localhost)")
    }
}

/// curl `--proto` value permitting exactly what `check_url` accepts.
pub fn protocols(url: &Url) -> &'static str {
    if url.scheme() == "http" {
        "=http"
    } else {
        "=https"
    }
}

/// How requests to a remote authenticate at the infrastructure layer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// No infrastructure authentication.
    #[default]
    None,
    /// Cloudflare Access, using `cloudflared access token`.
    Cloudflared,
}

impl Access {
    /// The header line to send to `url`, if any.
    fn header(self, url: &Url) -> Result<Option<String>> {
        match self {
            Self::None => Ok(None),
            Self::Cloudflared => {
                let origin = url.origin().ascii_serialization();
                let output = Command::new("cloudflared")
                    .args(["access", "token", "-app", &origin])
                    .output()
                    .context("cannot run cloudflared; install it or remove --access")?;
                let token = String::from_utf8(output.stdout).unwrap_or_default();
                let token = token.trim();
                if !output.status.success()
                    || token.is_empty()
                    || token.contains(char::is_whitespace)
                {
                    bail!(
                        "no Cloudflare Access token for {origin}\nhint: run `cloudflared access login {origin}`"
                    );
                }
                Ok(Some(format!("cf-access-token: {token}")))
            }
        }
    }
}

/// A parsed final response: the last header block curl dumped.
#[derive(Debug)]
pub struct Head {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// Reads curl's `--dump-header` file. Informational blocks are skipped.
    pub fn read(path: &Path) -> Result<Option<Self>> {
        let text = String::from_utf8_lossy(&fs::read(path)?).into_owned();
        let Some(block) = text
            .split("\r\n\r\n")
            .flat_map(|b| b.split("\n\n"))
            .filter(|b| b.trim_start().starts_with("HTTP/"))
            .last()
        else {
            return Ok(None);
        };
        let mut lines = block.lines().map(str::trim_end);
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .context("malformed HTTP status line")?;
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        Ok(Some(Self { status, headers }))
    }

    pub fn all<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> + 'a {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(move |(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn first(&self, name: &str) -> Option<&str> {
        self.all(name).next()
    }

    /// Supported `Mole` challenges, in order; malformed ones are skipped.
    pub fn challenges(&self) -> Vec<Challenge> {
        Challenge::parse(self.all("www-authenticate"))
    }

    /// `Mole-Credential`; `None` when absent, which carries no decision.
    pub fn mole_credential(&self) -> Result<Option<CredentialField>> {
        CredentialField::parse(self.all("mole-credential"))
            .map_err(|e| anyhow::anyhow!("malformed Mole-Credential: {e}"))
    }
}

/// A private scratch directory (mode 0700) for one exchange's files.
pub struct Scratch(tempfile::TempDir);

impl Scratch {
    pub fn new() -> Result<Self> {
        let mut builder = tempfile::Builder::new();
        builder.prefix("guac-");
        #[cfg(unix)]
        builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700));
        Ok(Self(
            builder
                .tempdir()
                .context("cannot create a private temporary directory")?,
        ))
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.path().join(name)
    }

    /// Writes a private (0600) file.
    pub fn write(&self, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = self.path(name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(&path)?.write_all(bytes)?;
        Ok(path)
    }
}

/// Outcome of one curl run with headers and body captured to files.
pub struct Run {
    /// curl's own exit status; 0 unless transport or `--fail` errors.
    pub exit: i32,
    pub head: Option<Head>,
    pub body: PathBuf,
    pub stderr: Vec<u8>,
}

/// Runs `curl -q <args> -D <head> -o <body>` with private capture files.
pub fn curl(scratch: &Scratch, tag: &str, args: &[OsString]) -> Result<Run> {
    let head = scratch.path(&format!("{tag}.head"));
    let body = scratch.path(&format!("{tag}.body"));
    let output = Command::new("curl")
        .arg("-q")
        .args(args)
        .arg("-D")
        .arg(&head)
        .arg("-o")
        .arg(&body)
        .stdin(std::process::Stdio::null())
        .output()
        .context("cannot run curl; is it installed?")?;
    let head = if head.exists() {
        Head::read(&head)?
    } else {
        None
    };
    if !body.exists() {
        fs::write(&body, [])?;
    }
    Ok(Run {
        exit: output.status.code().unwrap_or(1),
        head,
        body,
        stderr: output.stderr,
    })
}

/// A complete internal protocol response.
pub struct Response {
    pub head: Head,
    pub body: Vec<u8>,
}

/// One internal protocol request. `headers` may carry secrets.
pub fn request(
    method: &str,
    url: &Url,
    access: Access,
    headers: &[String],
    body: Option<&[u8]>,
) -> Result<Response> {
    check_url(url)?;
    let scratch = Scratch::new()?;
    let mut lines: Vec<String> = headers.to_vec();
    lines.extend(access.header(url)?);
    let mut args: Vec<OsString> = vec![
        "-sS".into(),
        "--globoff".into(),
        "--proto".into(),
        protocols(url).into(),
        "-X".into(),
        method.into(),
        "--max-filesize".into(),
        MAX_INTERNAL_BODY.to_string().into(),
        "--max-time".into(),
        "30".into(),
    ];
    if !lines.is_empty() {
        let mut file = lines.join("\n");
        file.push('\n');
        args.push("-H".into());
        let mut at = OsString::from("@");
        at.push(scratch.write("request.headers", file.as_bytes())?);
        args.push(at);
    }
    if let Some(body) = body {
        args.push("--data-binary".into());
        let mut at = OsString::from("@");
        at.push(scratch.write("request.body", body)?);
        args.push(at);
    }
    args.push(url.as_str().into());
    let run = curl(&scratch, "response", &args)?;
    // A head with a nonzero exit is still a failure, e.g. a truncated body (18).
    let (Some(head), 0) = (run.head, run.exit) else {
        bail!(
            "{method} {url} failed: {}",
            String::from_utf8_lossy(&run.stderr).trim()
        );
    };
    let body = fs::read(&run.body)?;
    Ok(Response { head, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_final_block_and_mole_fields() {
        let scratch = Scratch::new().unwrap();
        let path = scratch
            .write(
                "h",
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/2 401\r\nwww-authenticate: Basic realm=x\r\nWWW-Authenticate: Mole endorse-0002=\"\", realm=\"moderator\"\r\nMole-Credential: update-0001=\"\"\r\n\r\n",
            )
            .unwrap();
        let head = Head::read(&path).unwrap().unwrap();
        assert_eq!(head.status, 401);
        assert_eq!(head.challenges(), [Challenge::Endorse]);
        assert!(matches!(
            head.mole_credential().unwrap(),
            Some(CredentialField::Update(_))
        ));
        assert_eq!(decode("AQ=="), None);
        assert_eq!(decode("AR"), None); // Noncanonical trailing bits.
    }

    #[cfg(unix)]
    #[test]
    fn scratch_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::new().unwrap();
        let mode = fs::metadata(scratch.0.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
