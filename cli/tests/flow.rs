//! End to end: the `guac` binary and system curl against an in-process Anchor
//! and Moderator speaking the MOLE HTTP carriage.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    num::NonZeroU16,
    path::Path,
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use guac::{
    Anchor, AnchorSet, EndorsementPolicy, Moderator, PresentationOutcome, UpdatePolicy,
    http::{self as mole, Authorization, Challenge, CredentialField},
    protocol::EndorsementRequest,
    storage::{MemoryStore, Store},
};
use sha2::{Digest, Sha256};

const COST: u64 = 2;

struct Server {
    origin: String,
    anchor: Anchor,
    moderator: Moderator,
    store: MemoryStore,
    /// Authorization code -> (S256 challenge, redirect URI).
    codes: Mutex<HashMap<String, (String, String)>>,
    /// Grant route -> verifier owner binding.
    routes: Mutex<HashMap<String, Option<String>>>,
    approval: bool,
    counter: AtomicU64,
    plain_hits: AtomicU64,
    lose_next: AtomicBool,
    slow: AtomicBool,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next()?.to_owned(), parts.next()?.to_owned());
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let length = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

fn param(header: &str, name: &str) -> Option<String> {
    header.split(',').find_map(|part| {
        let (k, v) = part.trim().split_once('=')?;
        let k = k.rsplit(' ').next()?;
        (k.eq_ignore_ascii_case(name)).then(|| v.trim_matches('"').to_owned())
    })
}

type Reply = (u16, Vec<(String, String)>, Vec<u8>);

fn reply(status: u16, headers: &[(&str, String)], body: impl Into<Vec<u8>>) -> Reply {
    (
        status,
        headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
        body.into(),
    )
}

impl Server {
    fn handle(&self, request: Request) -> Option<Reply> {
        let auth = request
            .headers
            .get("authorization")
            .cloned()
            .unwrap_or_default();
        let path = request.path.split('?').next().unwrap_or_default();
        Some(match (request.method.as_str(), path) {
            ("GET", "/anchor/config") => {
                let config = self.anchor.configuration().clone();
                let mut value = serde_json::json!({
                    "grant-uri": "/anchor/grant",
                    "endorsement-type": 2,
                    "ciphersuite": "P256-SHA256",
                    "anchor-key": B64.encode(config.public_key()),
                    "issuance-epoch": B64.encode(config.epoch()),
                    "unknown-member": true,
                });
                if self.approval {
                    value["authorization-uri"] = "/approve?anchor=test".into();
                }
                reply(200, &[], value.to_string())
            }
            ("POST", "/anchor/grant") => {
                let guac_auth = request.headers.get("guac-authorization");
                let verifier = guac_auth.and_then(|h| param(h, "verifier"));
                mole::check_content_type(
                    request.headers.get("content-type")?,
                    mole::ENDORSEMENT_REQUEST,
                )
                .ok()?;
                let message = EndorsementRequest::from_bytes(&request.body).ok()?;
                let route = match request.headers.get("x-guac-grant") {
                    None => {
                        if self.approval {
                            let header = guac_auth?;
                            let code = param(header, "code")?;
                            let (challenge, redirect) = self.codes.lock().unwrap().remove(&code)?;
                            let verifier = verifier.clone()?;
                            if B64.encode(Sha256::digest(verifier.as_bytes())) != challenge
                                || param(header, "redirect-uri")? != redirect
                            {
                                return Some(reply(403, &[], "bad authorization"));
                            }
                        }
                        let route = format!("{:032x}", now() ^ rand_u64());
                        self.routes.lock().unwrap().insert(route.clone(), verifier);
                        route
                    }
                    Some(route) => {
                        if self.routes.lock().unwrap().remove(route) != Some(verifier) {
                            return Some(reply(409, &[], "grant expired or consumed"));
                        }
                        route.clone()
                    }
                };
                let response = self
                    .anchor
                    .grant(&self.store, &message, now(), now() + 60, NonZeroU16::MAX)
                    .ok()?;
                reply(
                    200,
                    &[
                        ("X-Guac-Grant", route),
                        ("Content-Type", mole::ENDORSEMENT_RESPONSE.into()),
                    ],
                    response.to_bytes(),
                )
            }
            ("GET", "/moderator/config") => {
                let c = self.moderator.configuration();
                let anchor = self.anchor.configuration().clone();
                reply(200, &[], serde_json::json!({
                    "issuance-uri": c.endpoint().as_str(),
                    "credential-keys": [
                        { "credential-type": 1, "ciphersuite": "unknown" },
                        { "credential-type": 1, "credential-key": B64.encode(c.public_key()), "ciphersuite": "P256-SHA256",
                          "balance-width": c.balance_bits(), "credential-context": B64.encode(c.credential_context()), "result-retention": 60 },
                    ],
                    "endorsements": [
                        { "endorsement-type": 99 },
                        { "endorsement-type": 2, "ciphersuite": "P256-SHA256", "issuance-epoch": B64.encode(anchor.epoch()),
                          "anchor-set": [B64.encode(anchor.public_key())] },
                    ],
                }).to_string())
            }
            ("POST", "/moderator/issue") => {
                let fresh = || {
                    let challenge = self.moderator.redemption_challenge(now()).unwrap();
                    reply(
                        401,
                        &[(
                            "WWW-Authenticate",
                            format!("{}, realm=\"moderator\"", Challenge::Redeem(challenge)),
                        )],
                        "",
                    )
                };
                let credential = |field: CredentialField| {
                    vec![
                        ("Mole-Credential", field.to_string()),
                        ("Cache-Control", "no-store".into()),
                    ]
                };
                match Authorization::parse(&auth).ok()? {
                    None => fresh(),
                    Some(Authorization::Recover(handle)) => {
                        assert!(request.body.is_empty());
                        match self.moderator.recover(&self.store, &handle, now()) {
                            Ok(update) => {
                                reply(200, &credential(CredentialField::Update(update)), "")
                            }
                            Err(_) => reply(404, &[], ""),
                        }
                    }
                    Some(Authorization::Present(_)) => reply(400, &[], ""),
                    Some(Authorization::Issue(request)) => match self
                        .moderator
                        .prepare_issuance(&request, 8, now())
                        .and_then(|issuance| {
                            if let Some(id) = issuance.replay_id()
                                && !self.store.insert_redemption(id)?
                            {
                                return Err(guac::Error::Replay);
                            }
                            Ok(issuance.into_response())
                        }) {
                        Ok(response) => {
                            reply(200, &credential(CredentialField::Response(response)), "")
                        }
                        Err(_) => fresh(),
                    },
                }
            }
            ("POST", "/counter") => {
                let binding = format!("POST {}/counter", self.origin);
                let fresh = || {
                    let challenge = self
                        .moderator
                        .presentation_challenge(COST, 0, binding.as_bytes(), now())
                        .unwrap();
                    reply(
                        401,
                        &[
                            ("WWW-Authenticate", "Mole endorse-0002=\"\"".into()),
                            (
                                "WWW-Authenticate",
                                Challenge::Present(challenge).to_string(),
                            ),
                        ],
                        "{\"error\":\"pay\"}",
                    )
                };
                let Some(Authorization::Present(presentation)) =
                    Authorization::parse(&auth).ok()?
                else {
                    return Some(fresh());
                };
                assert_eq!(
                    request.body, b"payload",
                    "the saved body must be replayed unchanged"
                );
                if self.slow.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1500));
                }
                let outcome = self.moderator.process(
                    &self.store,
                    &presentation,
                    COST,
                    0,
                    binding.as_bytes(),
                    UpdatePolicy::ReturnCredits(1),
                    now(),
                );
                let (status, body) = match &outcome {
                    Ok(PresentationOutcome::Accepted(_)) => (
                        200,
                        format!(
                            "{{\"counter\":{}}}",
                            self.counter.fetch_add(1, Ordering::SeqCst) + 1
                        ),
                    ),
                    Ok(PresentationOutcome::Recovered(_)) => (
                        409,
                        "{\"error\":\"presentation already accepted\"}".to_owned(),
                    ),
                    Err(_) => return Some(fresh()),
                };
                if self.lose_next.swap(false, Ordering::SeqCst) {
                    return None; // Accepted and committed, but the response is lost.
                }
                let update = outcome.ok()?.update().clone();
                reply(
                    status,
                    &[
                        (
                            "Mole-Credential",
                            CredentialField::Update(update).to_string(),
                        ),
                        ("Cache-Control", "no-store".into()),
                    ],
                    body,
                )
            }
            ("GET", "/plain") => {
                self.plain_hits.fetch_add(1, Ordering::SeqCst);
                reply(200, &[], "hello")
            }
            _ => reply(404, &[], "not found"),
        })
    }
}

fn rand_u64() -> u64 {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes).unwrap();
    u64::from_le_bytes(bytes)
}

fn serve(approval: bool) -> Arc<Server> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let anchor = Anchor::generate(b"epoch-1".to_vec()).unwrap();
    let set = AnchorSet::new(&[anchor.configuration().clone()]).unwrap();
    let moderator = Moderator::generate(
        &format!("{origin}/moderator/issue"),
        4,
        b"test".to_vec(),
        EndorsementPolicy::Required(set),
        60,
    )
    .unwrap();
    let server = Arc::new(Server {
        origin,
        anchor,
        moderator,
        store: MemoryStore::default(),
        codes: Mutex::default(),
        routes: Mutex::default(),
        approval,
        counter: AtomicU64::new(0),
        plain_hits: AtomicU64::new(0),
        lose_next: AtomicBool::new(false),
        slow: AtomicBool::new(false),
    });
    let shared = Arc::clone(&server);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let server = Arc::clone(&shared);
            std::thread::spawn(move || {
                let Some(request) = read_request(&mut stream) else {
                    return;
                };
                let Some((status, headers, body)) = server.handle(request) else {
                    return;
                };
                let mut head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (k, v) in headers {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            });
        }
    });
    server
}

fn guac(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_guac"));
    command
        .env("GUAC_HOME", home)
        .args(args)
        .stdin(Stdio::null());
    command
}

fn ok(home: &Path, args: &[&str]) -> String {
    let output = guac(home, args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn run(home: &Path, args: &[&str]) -> Output {
    guac(home, args).output().unwrap()
}

#[cfg(unix)]
#[test]
fn non_utf8_state_path_keeps_database_private() {
    use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(std::ffi::OsStr::from_bytes(b"state-\xff"));
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
    let database = home.join("guac.sqlite3");
    std::fs::write(&database, []).unwrap();
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644)).unwrap();
    ok(&home, &["status"]);
    assert_eq!(
        std::fs::metadata(database).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

fn balance(home: &Path, name: &str) -> u64 {
    let value: serde_json::Value =
        serde_json::from_str(&ok(home, &["--json", "credential", "show", name])).unwrap();
    value["balance"].as_u64().unwrap()
}

/// Requests an endorsement, playing the browser for approval-gated Anchors.
fn endorse(home: &Path, server: &Server) -> String {
    let mut child = guac(
        home,
        &["endorsement", "request", "--anchor", "a", "--no-browser"],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    if server.approval {
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let url = loop {
            let mut line = String::new();
            assert_ne!(
                stderr.read_line(&mut line).unwrap(),
                0,
                "no approval URL printed"
            );
            if let Some(url) = line
                .trim()
                .strip_prefix(&format!("{}/approve?", server.origin))
            {
                break url.to_owned();
            }
        };
        let query: HashMap<String, String> = url::form_urlencoded::parse(url.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["anchor"], "test");
        let redirect = query["redirect_uri"].clone();
        // A request with the wrong state is ignored, not fatal.
        let wrong = Command::new("curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                &format!("{redirect}?code=x&state=wrong"),
            ])
            .output()
            .unwrap();
        assert_eq!(wrong.stdout, b"400");
        server.codes.lock().unwrap().insert(
            "approved-code".into(),
            (query["code_challenge"].clone(), redirect.clone()),
        );
        let done = Command::new("curl")
            .args([
                "-s",
                &format!("{redirect}?code=approved-code&state={}", query["state"]),
            ])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&done.stdout).contains("Approved"));
        std::thread::spawn(move || std::io::copy(&mut stderr, &mut std::io::sink()));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn endorse_issue_spend_recover() {
    let server = serve(true);
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    let origin = &server.origin;
    ok(
        home,
        &["anchor", "add", "a", &format!("{origin}/anchor/config")],
    );
    ok(
        home,
        &[
            "moderator",
            "add",
            "m",
            &format!("{origin}/moderator/config"),
        ],
    );
    assert!(
        !run(
            home,
            &["anchor", "add", "a", &format!("{origin}/anchor/config")]
        )
        .status
        .success()
    );

    // Required endorsement is enforced before any redemption.
    let missing = run(home, &["credential", "issue", "--moderator", "m"]);
    assert!(String::from_utf8_lossy(&missing.stderr).contains("requires an Anchor endorsement"));

    let id = endorse(home, &server);
    assert!(id.starts_with("end_"), "{id}");
    assert_eq!(
        ok(
            home,
            &[
                "credential",
                "issue",
                "--moderator",
                "m",
                "--endorsement",
                &id,
                "--as",
                "c"
            ]
        )
        .trim(),
        "c: 8 credits"
    );
    assert!(
        !run(home, &["endorsement", "show", &id]).status.success(),
        "endorsement consumed by issuance"
    );

    let body = home.join("body");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let cwd = home.join(std::ffi::OsStr::from_bytes(b"cwd-\xff"));
        std::fs::create_dir(&cwd).unwrap();
        let output = guac(
            home,
            &[
                "curl",
                "--credential",
                "c",
                "--",
                "--cacert",
                "ca.pem",
                origin,
            ],
        )
        .current_dir(cwd)
        .output()
        .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("absolute CA path must be UTF-8"));
    }
    std::fs::write(&body, "payload").unwrap();
    let data = format!("@{}", body.display());
    let counter = format!("{origin}/counter");
    let spend = [
        "curl",
        "-c",
        "c",
        "--",
        "-X",
        "POST",
        "--data-binary",
        &data,
        &counter,
    ];
    // `--fail` still lets Guac read the 401 challenge headers.
    assert_eq!(
        ok(
            home,
            &[
                "curl",
                "-c",
                "c",
                "--",
                "-sSf",
                "-X",
                "POST",
                "--data-binary",
                &data,
                &counter
            ]
        ),
        "{\"counter\":1}"
    );
    assert_eq!(balance(home, "c"), 7);

    // Over budget: nothing is spent.
    let refused = run(
        home,
        &[
            "curl",
            "-c",
            "c",
            "--max-cost",
            "1",
            "--",
            "-X",
            "POST",
            "--data-binary",
            &data,
            &counter,
        ],
    );
    assert!(!refused.status.success());
    assert_eq!(balance(home, "c"), 7);

    // Unprotected responses are delivered once and spend nothing.
    assert_eq!(
        ok(home, &["curl", "-c", "c", "--", &format!("{origin}/plain")]),
        "hello"
    );
    assert_eq!(server.plain_hits.load(Ordering::SeqCst), 1);
    assert_eq!(balance(home, "c"), 7);

    // Lost response: credits stay pending; the saved request recovers them.
    server.lose_next.store(true, Ordering::SeqCst);
    let lost = run(home, &spend);
    assert_eq!(
        lost.status.code(),
        Some(75),
        "{}",
        String::from_utf8_lossy(&lost.stderr)
    );
    std::fs::write(&body, "changed after the fact").unwrap();
    let pending: serde_json::Value =
        serde_json::from_str(&ok(home, &["--json", "pending", "list"])).unwrap();
    let op = pending[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(pending[0]["kind"], "presentation");
    assert!(
        !run(home, &["credential", "show", "c"]).status.success(),
        "pending credential is not usable"
    );
    let retried = run(home, &["pending", "retry", &op]);
    assert!(
        retried.status.success(),
        "{}",
        String::from_utf8_lossy(&retried.stderr)
    );
    assert!(String::from_utf8_lossy(&retried.stderr).contains("original response is unavailable"));
    assert_eq!(
        server.counter.load(Ordering::SeqCst),
        2,
        "recovery never repeats the operation"
    );
    assert_eq!(balance(home, "c"), 6);
    std::fs::write(&body, "payload").unwrap();

    // Lost response, lookup-only recovery: no request is resent.
    server.lose_next.store(true, Ordering::SeqCst);
    assert_eq!(run(home, &spend).status.code(), Some(75));
    let pending: serde_json::Value =
        serde_json::from_str(&ok(home, &["--json", "pending", "list"])).unwrap();
    let op = pending[0]["id"].as_str().unwrap().to_owned();
    ok(home, &["pending", "recover", &op]);
    assert_eq!(server.counter.load(Ordering::SeqCst), 3);
    assert_eq!(balance(home, "c"), 5);

    // Two processes cannot spend one credential.
    server.slow.store(true, Ordering::SeqCst);
    let children: Vec<_> = (0..2)
        .map(|_| {
            guac(home, &spend)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let results: Vec<Output> = children
        .into_iter()
        .map(|c| c.wait_with_output().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|o| o.status.success()).count(),
        1,
        "{results:?}"
    );
    assert_eq!(server.counter.load(Ordering::SeqCst), 4);
    assert_eq!(balance(home, "c"), 4);

    let status: serde_json::Value = serde_json::from_str(&ok(home, &["--json", "status"])).unwrap();
    assert_eq!(status["credentials"][0]["balance"], 4);
    assert_eq!(status["pending"].as_array().unwrap().len(), 0);
}

#[test]
fn approval_needs_input() {
    let server = serve(true);
    let home = tempfile::tempdir().unwrap();
    ok(
        home.path(),
        &[
            "anchor",
            "add",
            "a",
            &format!("{}/anchor/config", server.origin),
        ],
    );
    let output = run(
        home.path(),
        &["--no-input", "endorsement", "request", "--anchor", "a"],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires approval in a browser"));
}

#[test]
fn plain_anchor_and_removal() {
    let server = serve(false);
    let home = tempfile::tempdir().unwrap();
    let home = home.path();
    ok(
        home,
        &[
            "anchor",
            "add",
            "a",
            &format!("{}/anchor/config", server.origin),
        ],
    );
    let id = endorse(home, &server);
    assert!(
        !run(home, &["endorsement", "remove", &id]).status.success(),
        "non-interactive removal needs --force"
    );
    ok(home, &["endorsement", "remove", "--force", &id]);
    assert_eq!(ok(home, &["endorsement", "list"]), "");
}
