//! Anchor endorsement: optional browser approval, then two grant exchanges.
//!
//! Browser approval is OAuth-shaped (RFC 8252 native app, loopback redirect,
//! S256 PKCE, RFC 7636). The authorization code is not exchanged for a token:
//! it authorizes exactly one grant session, presented with its verifier on the
//! opening grant request. The verifier also binds the session's second
//! exchange. Approval UI, Google sign-in, and Turnstile stay in the browser.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    num::NonZeroU16,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use guac::{Client, GrantStep, PendingGrant, protocol::EndorsementResponse};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    Output, held, hex_id,
    http::{self, encode},
    remote::AnchorDirectory,
    store::{self, Endorsement, Pending, PendingRow, Put, Store, Take},
};

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);

pub struct Options {
    pub open_browser: bool,
    pub interactive: bool,
    pub count: NonZeroU16,
}

/// An approved, unexchanged authorization code.
struct Approval {
    code: String,
    verifier: String,
    redirect_uri: String,
}

pub fn request(
    store: &mut Store,
    anchor: &str,
    directory: AnchorDirectory,
    options: &Options,
    out: &Output,
) -> Result<Vec<String>> {
    let config = directory.anchor.config()?;
    let approval = match &directory.authorization_uri {
        Some(uri) => Some(approve(uri, options, out)?),
        None => None,
    };
    let (request, pending) = Client.start_grant(&config, options.count);
    let mut headers = vec![format!("Content-Type: {}", guac::http::ENDORSEMENT_REQUEST)];
    if let Some(a) = &approval {
        headers.push(format!(
            "Guac-Authorization: code=\"{}\", verifier=\"{}\", redirect-uri=\"{}\"",
            a.code, a.verifier, a.redirect_uri
        ));
    }
    out.progress("Exchanging with the Anchor…");
    let response = http::request(
        "POST",
        &directory.grant_uri,
        directory.access,
        &headers,
        Some(&request.to_bytes()),
    )?;
    if response.head.status != 200 {
        bail!(
            "Anchor refused the grant (HTTP {}): {}",
            response.head.status,
            String::from_utf8_lossy(&response.body).trim()
        );
    }
    let route = response
        .head
        .first("x-guac-grant")
        .context("Anchor omitted its grant route (X-Guac-Grant)")?
        .to_owned();
    let step = pending.advance(&grant_response(&response)?)?;
    let GrantStep::Continue { request, pending } = step else {
        bail!("Anchor completed the grant in one exchange; unsupported");
    };
    let row = PendingRow {
        id: hex_id("op")?,
        record: Pending::Grant {
            anchor: anchor.to_owned(),
            directory,
            route,
            verifier: approval.map(|a| a.verifier),
            request: request.to_bytes(),
        },
        secret: pending.to_storage_bytes(),
        created_at: store::now(),
    };
    store.transition(None, Some(Put::Pending(&row)))?;
    finish(store, &row.id)
}

fn grant_response(response: &http::Response) -> Result<EndorsementResponse> {
    guac::http::check_content_type(
        response.head.first("content-type").unwrap_or(""),
        guac::http::ENDORSEMENT_RESPONSE,
    )
    .context("Anchor answered with the wrong media type")?;
    Ok(EndorsementResponse::from_bytes(&response.body)?)
}

/// Sends the saved second exchange; stores the endorsements on success.
pub fn finish(store: &mut Store, id: &str) -> Result<Vec<String>> {
    exchange(store, id).map_err(|e| held(id, e))
}

fn exchange(store: &mut Store, id: &str) -> Result<Vec<String>> {
    let row = store.pending(id)?;
    let Pending::Grant {
        anchor,
        directory,
        route,
        verifier,
        request,
    } = &row.record
    else {
        bail!("`{id}` is not a grant");
    };
    let pending = PendingGrant::from_storage_bytes(&row.secret, &directory.anchor.config()?)?;
    let mut headers = vec![
        format!("Content-Type: {}", guac::http::ENDORSEMENT_REQUEST),
        format!("X-Guac-Grant: {route}"),
    ];
    if let Some(verifier) = verifier {
        headers.push(format!("Guac-Authorization: verifier=\"{verifier}\""));
    }
    let response = http::request(
        "POST",
        &directory.grant_uri,
        directory.access,
        &headers,
        Some(request),
    )?;
    if response.head.status != 200 {
        bail!(
            "Anchor refused the exchange (HTTP {}): {}; expired or consumed grants cannot resume",
            response.head.status,
            String::from_utf8_lossy(&response.body).trim()
        );
    }
    let step = pending
        .advance(&grant_response(&response)?)
        .context("invalid Anchor response")?;
    let GrantStep::Complete(granted) = step else {
        bail!("Anchor asked for a third exchange; unsupported");
    };
    let endorsements = granted
        .iter()
        .map(|endorsement| {
            Ok(Endorsement {
                id: hex_id("end")?,
                anchor: anchor.clone(),
                directory: directory.clone(),
                secret: endorsement.to_storage_bytes(),
                created_at: store::now(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    store.transition(
        Some(Take::Pending(id)),
        Some(Put::Endorsements(&endorsements)),
    )?;
    Ok(endorsements.into_iter().map(|e| e.id).collect())
}

fn approve(authorization_uri: &Url, options: &Options, out: &Output) -> Result<Approval> {
    if !options.interactive {
        bail!(
            "this Anchor requires approval in a browser\nhint: rerun `guac endorsement request` without --no-input"
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .context("cannot listen on loopback for the approval callback")?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}/callback",
        listener.local_addr()?.port()
    );
    let state = encode(&http::random(32)?);
    let verifier = encode(&http::random(32)?);
    let mut url = authorization_uri.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", "guac-cli")
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", &state)
        .append_pair(
            "code_challenge",
            &encode(&Sha256::digest(verifier.as_bytes())),
        )
        .append_pair("code_challenge_method", "S256");
    out.notice(&format!(
        "Approve this endorsement in your browser:\n  {url}"
    ));
    if options.open_browser {
        open(url.as_str());
    }
    let code = callback(&listener, &state, Instant::now() + APPROVAL_TIMEOUT)?;
    Ok(Approval {
        code,
        verifier,
        redirect_uri,
    })
}

fn open(url: &str) {
    let mut command = if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else {
        std::process::Command::new("xdg-open")
    };
    // Best effort: the URL is already printed.
    let _ = command
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Waits for `GET /callback?code=…&state=…`; ignores unrelated requests.
fn callback(listener: &TcpListener, state: &str, deadline: Instant) -> Result<String> {
    listener.set_nonblocking(true)?;
    loop {
        if Instant::now() >= deadline {
            bail!("timed out waiting for browser approval");
        }
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        if let Some(code) = answer(stream, state, deadline)? {
            return Ok(code);
        }
    }
}

fn answer(mut stream: TcpStream, state: &str, deadline: Instant) -> Result<Option<String>> {
    stream.set_nonblocking(false)?;
    let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
    let mut buffer = Zeroizing::new([0; 8192]);
    let mut length = 0;
    while length < buffer.len() && !buffer[..length].windows(4).any(|w| w == b"\r\n\r\n") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut buffer[length..]) {
            Ok(0) | Err(_) => return Ok(None),
            Ok(n) => length += n,
        }
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(None);
    }
    stream.set_write_timeout(Some(remaining))?;
    let head = String::from_utf8_lossy(&buffer[..length]).into_owned();
    let target = head
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("GET "))
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or("");
    let reply = |mut stream: TcpStream, status: &str, text: &str| {
        let body = format!("<!doctype html><meta charset=utf-8><title>guac</title><p>{text}</p>");
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    };
    let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
        reply(stream, "400 Bad Request", "Bad request.");
        return Ok(None);
    };
    if url.path() != "/callback" {
        reply(stream, "404 Not Found", "Not found.");
        return Ok(None);
    }
    let query = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    if query("state").as_deref() != Some(state) {
        reply(
            stream,
            "400 Bad Request",
            "This approval does not belong to the waiting guac command.",
        );
        return Ok(None);
    }
    if let Some(error) = query("error") {
        reply(
            stream,
            "200 OK",
            "Approval declined. You can close this window.",
        );
        bail!("browser approval failed: {error}");
    }
    match query("code") {
        Some(code)
            if !code.is_empty()
                && code.len() <= 256
                // Printable ASCII (RFC 6749 VSCHAR) minus `"` and `\`: the code is
                // sent unescaped in the quoted-string Guac-Authorization header.
                && code
                    .bytes()
                    .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\') =>
        {
            reply(
                stream,
                "200 OK",
                "Approved. Return to your terminal; you can close this window.",
            );
            Ok(Some(code))
        }
        _ => {
            reply(stream, "400 Bad Request", "Invalid authorization code.");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trickling_callback_cannot_extend_approval_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let sender = std::thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(1);
            while Instant::now() < end && client.write_all(b"x").is_ok() {
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let start = Instant::now();
        let result = callback(&listener, "state", start + Duration::from_millis(100));
        let elapsed = start.elapsed();
        sender.join().unwrap();
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(elapsed < Duration::from_millis(800), "{elapsed:?}");
    }
}
