//! `guac curl`: one HTTP transfer through the system curl, paying with a
//! credential when the server answers with a MOLE challenge.
//!
//! Guac owns the exchange: it fetches the challenge with the request itself,
//! presents the credential, saves the exact request beside the pending
//! presentation, sends it, and stores the credential update from the response
//! headers before releasing the body. Only a documented subset of curl options
//! is accepted, so Guac controls authorization, redirects, retries and output.

use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
    path::PathBuf,
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use guac::{
    Client, CredentialOutcome, PendingPresentation,
    http::{Authorization, Challenge, CredentialField},
    protocol::CredentialUpdate,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    Output, held, hex_id,
    http::{self, Run, Scratch},
    remote::b64,
    store::{self, Credential, Pending, PendingRow, Put, Store, Take},
};

/// Request bodies and header files are snapshotted; this bounds each.
const MAX_SNAPSHOT: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Spec {
    Flag,
    Value,
    /// `@file` and `@-` are read once and replayed from a snapshot.
    File,
    /// `@file` allowed; inline values are checked for `Authorization`.
    Header,
    Output,
    /// A file curl reads at send time; made absolute for retries elsewhere.
    Path,
}

/// The supported curl subset. Anything else is rejected before any request.
const OPTIONS: &[(Option<char>, &str, Spec)] = &[
    (Some('X'), "request", Spec::Value),
    (Some('H'), "header", Spec::Header),
    (Some('d'), "data", Spec::File),
    (None, "data-binary", Spec::File),
    (None, "data-raw", Spec::Value),
    (None, "json", Spec::File),
    (Some('o'), "output", Spec::Output),
    (Some('A'), "user-agent", Spec::Value),
    (Some('e'), "referer", Spec::Value),
    (Some('m'), "max-time", Spec::Value),
    (None, "connect-timeout", Spec::Value),
    (None, "cacert", Spec::Path),
    (None, "compressed", Spec::Flag),
    (Some('s'), "silent", Spec::Flag),
    (Some('S'), "show-error", Spec::Flag),
    (Some('f'), "fail", Spec::Flag),
    (None, "fail-with-body", Spec::Flag),
    (Some('i'), "include", Spec::Flag),
    (Some('I'), "head", Spec::Flag),
    (None, "http1.1", Spec::Flag),
    (None, "http2", Spec::Flag),
];

pub const SUPPORTED: &str = "-X -H -d --data-binary --data-raw --json -o -A -e -m --connect-timeout --cacert --compressed -s -S -f --fail-with-body -i -I --http1.1 --http2";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Arg {
    Text(String),
    /// `@` followed by the path of snapshot `index`.
    Snapshot(usize),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Snapshot(#[serde(with = "b64")] Vec<u8>);

/// The exact request, replayable unchanged after an interruption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedRequest {
    url: Url,
    args: Vec<Arg>,
    snapshots: Vec<Snapshot>,
    /// `None`: standard output.
    output: Option<PathBuf>,
}

fn read_source(source: &str, stdin_used: &mut bool) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if source == "-" {
        if std::mem::replace(stdin_used, true) {
            bail!("standard input can be read only once");
        }
        std::io::stdin()
            .take(MAX_SNAPSHOT + 1)
            .read_to_end(&mut bytes)?;
    } else {
        fs::File::open(source)
            .with_context(|| format!("cannot read {source}"))?
            .take(MAX_SNAPSHOT + 1)
            .read_to_end(&mut bytes)?;
    }
    if bytes.len() as u64 > MAX_SNAPSHOT {
        bail!("{source} is larger than {MAX_SNAPSHOT} bytes");
    }
    Ok(bytes)
}

fn no_authorization(lines: &str) -> Result<()> {
    for line in lines.lines() {
        if let Some((name, _)) = line.split_once([':', ';'])
            && name.trim().eq_ignore_ascii_case("authorization")
        {
            bail!("guac curl sets Authorization itself; remove your Authorization header");
        }
    }
    Ok(())
}

impl SavedRequest {
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Parses and validates curl arguments, snapshotting `@file` inputs.
    pub fn parse(raw: &[OsString]) -> Result<Self> {
        let raw = raw
            .iter()
            .map(|a| {
                a.to_str()
                    .map(str::to_owned)
                    .context("curl arguments must be UTF-8")
            })
            .collect::<Result<Vec<_>>>()?;
        let (mut args, mut snapshots, mut output) = (Vec::new(), Vec::new(), None);
        let mut url = None;
        let mut stdin_used = false;
        let mut output_seen = false;
        let mut queue = raw.into_iter();
        while let Some(arg) = queue.next() {
            let (spec, name, attached) = if let Some(long) = arg.strip_prefix("--") {
                let (_, name, spec) =
                    OPTIONS
                        .iter()
                        .find(|(_, n, _)| *n == long)
                        .with_context(|| {
                            format!("unsupported curl option --{long}\nsupported: {SUPPORTED}")
                        })?;
                (*spec, format!("--{name}"), None)
            } else if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.is_empty()) {
                // Short options may be bundled (`-sSf`); a value option takes the rest.
                let mut chars = cluster.char_indices();
                let mut found = None;
                for (i, c) in chars.by_ref() {
                    let (_, _, spec) = OPTIONS
                        .iter()
                        .find(|(s, _, _)| *s == Some(c))
                        .with_context(|| {
                            format!("unsupported curl option -{c}\nsupported: {SUPPORTED}")
                        })?;
                    if *spec == Spec::Flag {
                        args.push(Arg::Text(format!("-{c}")));
                    } else {
                        let rest = &cluster[i + c.len_utf8()..];
                        found = Some((
                            *spec,
                            format!("-{c}"),
                            (!rest.is_empty()).then(|| rest.to_owned()),
                        ));
                        break;
                    }
                }
                match found {
                    Some(found) => found,
                    None => continue,
                }
            } else {
                if url.replace(arg).is_some() {
                    bail!("guac curl sends exactly one URL");
                }
                continue;
            };
            if spec == Spec::Flag {
                args.push(Arg::Text(name));
                continue;
            }
            let value = match attached {
                Some(value) => value,
                None => queue
                    .next()
                    .with_context(|| format!("{name} needs a value"))?,
            };
            match spec {
                Spec::Output => {
                    if std::mem::replace(&mut output_seen, true) {
                        bail!("only one --output is supported");
                    }
                    // Absolute, so `guac pending retry` from elsewhere writes the same file.
                    output = match value.as_str() {
                        "-" => None,
                        path => Some(std::path::absolute(path)?),
                    };
                }
                Spec::Path => {
                    args.push(Arg::Text(name));
                    args.push(Arg::Text(
                        std::path::absolute(&value)?
                            .to_str()
                            .context("absolute CA path must be UTF-8")?
                            .to_owned(),
                    ));
                }
                Spec::File | Spec::Header if value.starts_with('@') => {
                    let bytes = read_source(&value[1..], &mut stdin_used)?;
                    if spec == Spec::Header {
                        no_authorization(&String::from_utf8_lossy(&bytes))?;
                    }
                    args.push(Arg::Text(name));
                    args.push(Arg::Snapshot(snapshots.len()));
                    snapshots.push(Snapshot(bytes));
                }
                _ => {
                    if spec == Spec::Header {
                        no_authorization(&value)?;
                    }
                    args.push(Arg::Text(name));
                    args.push(Arg::Text(value));
                }
            }
        }
        let url = url.context("guac curl needs a URL")?;
        let url = Url::parse(&url).with_context(|| format!("invalid URL {url}"))?;
        http::check_url(&url)?;
        Ok(Self {
            url,
            args,
            snapshots,
            output,
        })
    }

    /// curl arguments; `authorization` travels in a private header file.
    fn argv(
        &self,
        scratch: &Scratch,
        tag: &str,
        authorization: Option<&str>,
    ) -> Result<Vec<OsString>> {
        let mut argv: Vec<OsString> = vec![
            "--no-progress-meter".into(),
            // `[1-3]` and `{a,b}` in a URL must not fan out into many requests.
            "--globoff".into(),
            "--proto".into(),
            http::protocols(&self.url).into(),
        ];
        for arg in &self.args {
            argv.push(match arg {
                Arg::Text(text) => text.into(),
                Arg::Snapshot(index) => {
                    let snapshot = self
                        .snapshots
                        .get(*index)
                        .context("corrupt saved request")?;
                    let mut at = OsString::from("@");
                    at.push(scratch.write(&format!("{tag}.{index}"), &snapshot.0)?);
                    at
                }
            });
        }
        if let Some(authorization) = authorization {
            argv.push("-H".into());
            let mut at = OsString::from("@");
            at.push(scratch.write(
                &format!("{tag}.authorization"),
                format!("Authorization: {authorization}\n").as_bytes(),
            )?);
            argv.push(at);
        }
        argv.push(self.url.as_str().into());
        Ok(argv)
    }

    /// Releases a response body where the user asked for it.
    fn deliver(&self, run: &Run) -> Result<()> {
        match &self.output {
            Some(path) => {
                fs::copy(&run.body, path)
                    .with_context(|| format!("cannot write {}", path.display()))?;
            }
            None => {
                let mut stdout = std::io::stdout().lock();
                std::io::copy(&mut fs::File::open(&run.body)?, &mut stdout)?;
                stdout.flush()?;
            }
        }
        Ok(())
    }
}

fn exit(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn replay_stderr(run: &Run) {
    let _ = std::io::stderr().write_all(&run.stderr);
}

pub fn run(
    store: &mut Store,
    credential: &str,
    max_cost: Option<u64>,
    args: &[OsString],
    out: &Output,
) -> Result<ExitCode> {
    let credential = store.credential(credential)?;
    let request = SavedRequest::parse(args)?;
    let scratch = Scratch::new()?;
    let first = http::curl(
        &scratch,
        "challenge",
        &request.argv(&scratch, "challenge", None)?,
    )?;
    let challenges = match first.head.as_ref().filter(|h| h.status == 401) {
        Some(head) => head.challenges(),
        None => Vec::new(),
    };
    let config = credential.directory.config()?;
    let Some(challenge) = Challenge::presentation(&challenges, &config) else {
        if challenges
            .iter()
            .any(|c| matches!(c, Challenge::Present(_)))
        {
            bail!(
                "this server does not accept credential `{}` (different Moderator context); nothing was spent",
                credential.name
            );
        }
        // Not a usable MOLE challenge: this was the response. Never send it twice.
        replay_stderr(&first);
        if first.head.is_some() {
            request.deliver(&first)?;
        }
        return Ok(exit(first.exit));
    };
    let cost = challenge.cost();
    if let Some(max) = max_cost
        && cost > max
    {
        bail!("server asks for {cost} credits, above --max-cost {max}; nothing was spent");
    }
    if cost > credential.balance {
        bail!(
            "credential `{}` has {} credits; this request costs {cost}\nhint: run `guac credential issue` for a fresh credential",
            credential.name,
            credential.balance
        );
    }
    let token = guac::Credential::from_storage_bytes(&credential.secret, &config)?;
    let pending = Client.present(token, challenge).map_err(|e| match e.error {
        guac::Error::Mismatch => anyhow::anyhow!(
            "this server does not accept credential `{}` (different Moderator context); nothing was spent",
            credential.name
        ),
        error => anyhow::anyhow!("cannot present credential: {error}; nothing was spent"),
    })?;
    let row = PendingRow {
        id: hex_id("op")?,
        record: Pending::Presentation {
            credential: credential.name.clone(),
            moderator: credential.moderator.clone(),
            directory: credential.directory.clone(),
            cost,
            authorization: Authorization::Present(pending.presentation().clone()).to_string(),
            request,
        },
        secret: pending.to_storage_bytes(),
        created_at: store::now(),
    };
    store
        .transition(
            Some(Take::Credential(&credential)),
            Some(Put::Pending(&row)),
        )
        .context("cannot save the pending presentation; nothing was sent")?;
    out.progress(&format!(
        "Spending {cost} credit(s) from `{}`…",
        credential.name
    ));
    send(store, &row.id, out)
}

/// Sends a saved presentation request and settles the credential update.
pub fn send(store: &mut Store, id: &str, out: &Output) -> Result<ExitCode> {
    let row = store.pending(id)?;
    let Pending::Presentation { request, .. } = &row.record else {
        bail!("`{id}` is not a presentation");
    };
    let scratch = Scratch::new()?;
    // Until the update is stored, every failure leaves the exchange pending.
    let (run, status) = settle(store, &row, &scratch, out).map_err(|e| held(&row.id, e))?;
    if status == 409 {
        out.notice("Recovered the credential update of an already-accepted request. The operation was not repeated; its original response is unavailable.");
    }
    request
        .deliver(&run)
        .context("the credential update was saved, but the response could not be delivered")?;
    Ok(exit(run.exit))
}

fn settle(
    store: &mut Store,
    row: &PendingRow,
    scratch: &Scratch,
    out: &Output,
) -> Result<(Run, u16)> {
    let Pending::Presentation {
        authorization,
        request,
        ..
    } = &row.record
    else {
        bail!("`{}` is not a presentation", row.id);
    };
    let run = http::curl(
        scratch,
        "request",
        &request.argv(scratch, "request", Some(authorization))?,
    )?;
    replay_stderr(&run);
    let Some(head) = &run.head else {
        bail!("no response from the server");
    };
    let status = head.status;
    // Without an update the exchange stays pending: leave the requested output untouched.
    let update = match head.mole_credential()? {
        Some(CredentialField::Update(update)) => update,
        None => bail!("server answered HTTP {status} without a credential update"),
        Some(_) => bail!("server answered HTTP {status} with an issuance response"),
    };
    store_update(store, row, &update, out)?;
    Ok((run, status))
}

/// Recovers the recorded update without repeating the request: an empty POST
/// to the Redeem & Issue endpoint with the presentation's recovery handle.
pub fn recover(store: &mut Store, id: &str, out: &Output) -> Result<()> {
    let row = store.pending(id)?;
    let Pending::Presentation { directory, .. } = &row.record else {
        bail!("`{id}` is not a presentation; only presentations can be recovered");
    };
    let pending = PendingPresentation::from_storage_bytes(&row.secret, &directory.config()?)?;
    let authorization = Authorization::Recover(pending.recovery_handle());
    let response = http::request(
        "POST",
        &directory.issuance_uri,
        directory.access,
        &[format!("Authorization: {authorization}")],
        Some(&[]),
    )
    .map_err(|e| held(id, e))?;
    match (response.head.status, response.head.mole_credential()) {
        (200, Ok(Some(CredentialField::Update(update)))) => store_update(store, &row, &update, out),
        (404, Ok(None)) => Err(held(
            id,
            anyhow::anyhow!(
                "the Moderator has no recoverable result: the request was not accepted, or recovery expired"
            ),
        )),
        (status, Err(e)) => Err(held(id, e.context(format!("HTTP {status}")))),
        (status, Ok(_)) => Err(held(
            id,
            anyhow::anyhow!("unexpected recovery response (HTTP {status})"),
        )),
    }
}

/// Settles the pending presentation with `update`.
fn store_update(
    store: &mut Store,
    row: &PendingRow,
    update: &CredentialUpdate,
    out: &Output,
) -> Result<()> {
    let Pending::Presentation {
        credential,
        moderator,
        directory,
        ..
    } = &row.record
    else {
        bail!("`{}` is not a presentation", row.id);
    };
    let pending = PendingPresentation::from_storage_bytes(&row.secret, &directory.config()?)?;
    match pending.finish(update) {
        Ok(CredentialOutcome::Replaced(token)) => {
            let next = Credential {
                name: credential.clone(),
                moderator: moderator.clone(),
                directory: directory.clone(),
                secret: token.to_storage_bytes(),
                balance: token.balance(),
                created_at: store::now(),
            };
            store.transition(Some(Take::Pending(&row.id)), Some(Put::Credential(&next)))?;
            out.progress(&format!("`{credential}` has {} credits left", next.balance));
        }
        Ok(CredentialOutcome::Consumed) => {
            store.transition(Some(Take::Pending(&row.id)), None)?;
            out.notice(&format!(
                "The server ended credential `{credential}`; no credits left"
            ));
        }
        Err(e) => bail!("invalid credential update: {}", e.error),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<SavedRequest> {
        SavedRequest::parse(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn accepts_the_subset_and_rejects_the_rest() {
        let request = parse(&[
            "-sSfXPOST",
            "-H",
            "Content-Type: application/json",
            "--data-raw",
            "{}",
            "-o",
            "out",
            "https://a.example/x",
        ])
        .unwrap();
        assert_eq!(
            request.output,
            Some(std::env::current_dir().unwrap().join("out"))
        );
        assert!(
            parse(&["-o", "-", "https://a.example/"])
                .unwrap()
                .output
                .is_none()
        );
        for bad in [
            &["-L", "https://a.example/"][..],
            &["--location", "https://a.example/"],
            &["--retry", "3", "https://a.example/"],
            &["-v", "https://a.example/"],
            &["https://a.example/", "https://b.example/"],
            &["-H", "authorization: Basic x", "https://a.example/"],
            &["http://a.example/"],
            &["--request=POST", "https://a.example/"],
            &["-o", "a", "-o", "b", "https://a.example/"],
            &[],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn snapshots_files_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("body");
        fs::write(&path, b"first").unwrap();
        let request = parse(&[
            "--data-binary",
            &format!("@{}", path.display()),
            "https://a.example/",
        ])
        .unwrap();
        fs::write(&path, b"changed").unwrap();
        assert_eq!(request.snapshots[0].0, b"first");
    }
}
