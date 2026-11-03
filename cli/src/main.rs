//! `guac`: obtain MOLE endorsements and credentials, and spend them with curl.

#![forbid(unsafe_code)]

mod curl;
mod grant;
mod http;
mod issue;
mod remote;
mod store;

use std::{
    ffi::OsString,
    io::{BufRead, IsTerminal, Write},
    num::NonZeroU16,
    process::ExitCode,
};

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use url::Url;

use crate::{
    http::Access,
    remote::{AnchorDirectory, ModeratorDirectory},
    store::{Kind, Pending, Store, Take},
};

/// Exit status when credits are held in a pending exchange (EX_TEMPFAIL).
const EXIT_PENDING: u8 = 75;

const EXAMPLES: &str = "\
Examples:
  guac anchor add work https://anchor.example/config
  guac moderator add api https://moderator.example/config
  guac endorsement request --anchor work
  guac credential issue --moderator api --endorsement end_7f3a91c2d4e5 --as work-api
  guac curl --credential work-api -- -X POST https://api.example/counter
  guac status

State lives in $GUAC_HOME (default: the platform data directory, e.g. ~/.local/share/guac).
Exit status: curl's own for completed requests, 75 when credits are left pending, 1 on errors.";

#[derive(Parser)]
#[command(name = "guac", version, about = "Obtain MOLE endorsements and credentials, and spend them with curl", after_help = EXAMPLES)]
struct Cli {
    /// Machine-readable output for management commands.
    #[arg(long, global = true)]
    json: bool,
    /// Only errors and required prompts on standard error.
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Never prompt or open a browser; fail instead.
    #[arg(long, global = true)]
    no_input: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage Anchors, which endorse clients.
    #[command(subcommand)]
    Anchor(Remote),
    /// Manage Moderators, which turn endorsements into credits.
    #[command(subcommand)]
    Moderator(Remote),
    /// Request and manage Anchor endorsements.
    #[command(subcommand)]
    Endorsement(EndorsementCommand),
    /// Issue and manage credit-bearing credentials.
    #[command(subcommand)]
    Credential(CredentialCommand),
    /// Send one HTTP request with curl, paying with a credential if challenged.
    #[command(after_help = curl_help())]
    Curl(CurlArgs),
    /// Inspect and resolve interrupted exchanges.
    #[command(subcommand)]
    Pending(PendingCommand),
    /// Summarize local state. Makes no network requests.
    Status,
}

fn curl_help() -> String {
    format!(
        "Guac options go before `--`, curl options after. Supported curl options:\n  {}\n\
         `@file` and `@-` inputs are read once, so a retry sends identical bytes.\n\
         The response body goes to standard output or -o; Guac saves the credential update first.\n\n\
         Example:\n  guac curl --credential work-api -- --fail-with-body -X POST https://api.example/counter",
        curl::SUPPORTED
    )
}

#[derive(Subcommand)]
enum Remote {
    /// Fetch, validate and save a directory under NAME.
    Add {
        name: String,
        /// Directory URL, e.g. <https://anchor.example/config>.
        url: Url,
        /// Infrastructure authentication for its requests.
        #[arg(long, value_enum, default_value_t = Access::None)]
        access: Access,
        /// Replace an existing entry with the same name.
        #[arg(short, long)]
        force: bool,
    },
    List,
    /// Show the saved public configuration.
    Show {
        name: String,
    },
    Remove {
        name: String,
    },
}

#[derive(Subcommand)]
enum EndorsementCommand {
    /// Obtain an endorsement; opens a browser when the Anchor asks for approval.
    Request {
        #[arg(long)]
        anchor: String,
        /// Print the approval URL instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
        /// Endorsements to ask for; the Anchor may grant fewer.
        #[arg(long, default_value_t = NonZeroU16::MIN)]
        count: NonZeroU16,
    },
    List,
    Show {
        id: String,
    },
    /// Delete an unused endorsement.
    Remove {
        id: String,
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum CredentialCommand {
    /// Redeem an endorsement (if the Moderator requires one) for a credential.
    Issue {
        #[arg(long)]
        moderator: String,
        #[arg(long)]
        endorsement: Option<String>,
        /// Credential name [default: the Moderator name].
        #[arg(long = "as")]
        name: Option<String>,
    },
    List,
    Show {
        name: String,
    },
    Rename {
        old: String,
        new: String,
    },
    /// Delete a credential and its credits.
    Remove {
        name: String,
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Args)]
struct CurlArgs {
    /// Credential to pay with.
    #[arg(short, long)]
    credential: String,
    /// Refuse challenges costing more than this many credits.
    #[arg(long)]
    max_cost: Option<u64>,
    /// curl options and URL.
    #[arg(last = true, required = true)]
    args: Vec<OsString>,
}

#[derive(Subcommand)]
enum PendingCommand {
    List,
    Show {
        id: String,
    },
    /// Resend the saved request unchanged and settle its result.
    Retry {
        id: String,
    },
    /// Fetch a presentation's recorded result without resending its request.
    Recover {
        id: String,
    },
    /// Discard an exchange. Its credits or endorsement are lost.
    Forget {
        id: String,
        #[arg(short, long)]
        force: bool,
    },
}

/// Credits are held in a pending exchange the user can retry.
#[derive(Debug)]
struct Unresolved(String);

impl std::fmt::Display for Unresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unresolved {}

/// Wraps a failure that leaves pending exchange `id` in place (exit 75).
pub fn held(id: &str, error: anyhow::Error) -> anyhow::Error {
    if error.is::<Unresolved>() {
        return error;
    }
    Unresolved(format!(
        "{error:#}\nhint: `{id}` is still pending; `guac pending retry {id}` resends it unchanged, for a presentation `guac pending recover {id}` fetches its recorded result without resending (both time-limited), `guac pending forget {id}` discards it"
    ))
    .into()
}

/// Human messages on stderr; data on stdout.
pub struct Output {
    json: bool,
    quiet: bool,
}

impl Output {
    /// Progress and hints, suppressed by --quiet.
    fn progress(&self, message: &str) {
        if !self.quiet {
            eprintln!("{message}");
        }
    }

    /// Messages the user must see.
    fn notice(&self, message: &str) {
        eprintln!("{message}");
    }

    fn data(&self, value: Value, human: impl FnOnce() -> String) {
        if self.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
        } else {
            let text = human();
            if !text.is_empty() {
                println!("{text}");
            }
        }
    }
}

pub fn hex_id(prefix: &str) -> Result<String> {
    let bytes = http::random(6)?;
    Ok(format!(
        "{prefix}_{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

fn confirm(question: &str, force: bool, no_input: bool) -> Result<()> {
    if force {
        return Ok(());
    }
    if no_input || !std::io::stdin().is_terminal() {
        bail!("{question}\nhint: pass --force to confirm");
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if matches!(answer.trim(), "y" | "Y" | "yes") {
        Ok(())
    } else {
        bail!("cancelled")
    }
}

fn age(created_at: i64) -> String {
    let seconds = (store::now() - created_at).max(0);
    match seconds {
        s if s < 120 => format!("{s}s ago"),
        s if s < 7200 => format!("{}m ago", s / 60),
        s if s < 172_800 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}

fn table(rows: Vec<Vec<String>>) -> String {
    let widths: Vec<usize> = (0..rows.first().map_or(0, Vec::len))
        .map(|i| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0))
        .collect();
    rows.iter()
        .map(|row| {
            row.iter()
                .zip(&widths)
                .map(|(cell, width)| format!("{cell:width$}"))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn pending_json(row: &store::PendingRow) -> Value {
    let mut value =
        json!({ "id": row.id, "kind": row.record.kind(), "created_at": row.created_at });
    match &row.record {
        Pending::Grant { anchor, .. } => value["anchor"] = json!(anchor),
        Pending::Issuance {
            credential,
            moderator,
            ..
        } => {
            value["credential"] = json!(credential);
            value["moderator"] = json!(moderator);
        }
        Pending::Presentation {
            credential,
            moderator,
            cost,
            request,
            ..
        } => {
            value["credential"] = json!(credential);
            value["moderator"] = json!(moderator);
            value["cost"] = json!(cost);
            value["url"] = json!(request.url().as_str());
        }
    }
    value
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let out = Output {
        json: cli.json,
        quiet: cli.quiet,
    };
    match run(cli, &out) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            if error.downcast_ref::<Unresolved>().is_some() {
                ExitCode::from(EXIT_PENDING)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn remote(store: &Store, kind: Kind, command: Remote, out: &Output) -> Result<()> {
    match command {
        Remote::Add {
            name,
            url,
            access,
            force,
        } => {
            let value = match kind {
                Kind::Anchor => {
                    let directory = remote::fetch_anchor(&url, access)?;
                    store.put_remote(kind, &name, &directory, force)?;
                    serde_json::to_value(&directory)?
                }
                Kind::Moderator => {
                    let directory = remote::fetch_moderator(&url, access)?;
                    store.put_remote(kind, &name, &directory, force)?;
                    serde_json::to_value(&directory)?
                }
            };
            out.data(json!({ "name": name, "directory": value }), || name.clone());
        }
        Remote::List => {
            let rows: Vec<(String, Value)> = store.remotes(kind)?;
            out.data(
                json!(
                    rows.iter()
                        .map(|(n, d)| json!({ "name": n, "directory": d }))
                        .collect::<Vec<_>>()
                ),
                || {
                    table(
                        rows.iter()
                            .map(|(n, d)| {
                                vec![n.clone(), d["url"].as_str().unwrap_or("").to_owned()]
                            })
                            .collect(),
                    )
                },
            );
        }
        Remote::Show { name } => {
            let value: Value = store.remote(kind, &name)?;
            out.data(json!({ "name": name, "directory": value }), || {
                let mut lines = vec![format!("name: {name}")];
                if let Some(object) = value.as_object() {
                    lines.extend(object.iter().map(|(k, v)| {
                        format!(
                            "{k}: {}",
                            v.as_str().map_or_else(|| v.to_string(), str::to_owned)
                        )
                    }));
                }
                lines.join("\n")
            });
        }
        Remote::Remove { name } => {
            store.remove_remote(kind, &name)?;
            out.progress(&format!(
                "Removed `{name}`. Saved endorsements and credentials keep working."
            ));
        }
    }
    Ok(())
}

fn run(cli: Cli, out: &Output) -> Result<ExitCode> {
    let mut store = Store::open()?;
    match cli.command {
        Command::Anchor(command) => remote(&store, Kind::Anchor, command, out)?,
        Command::Moderator(command) => remote(&store, Kind::Moderator, command, out)?,
        Command::Endorsement(command) => match command {
            EndorsementCommand::Request {
                anchor,
                no_browser,
                count,
            } => {
                let saved: AnchorDirectory = store.remote(Kind::Anchor, &anchor)?;
                let directory = remote::fetch_anchor(&saved.url, saved.access)?;
                store.put_remote(Kind::Anchor, &anchor, &directory, true)?;
                let options = grant::Options {
                    open_browser: !no_browser,
                    interactive: !cli.no_input,
                    count,
                };
                let ids = grant::request(&mut store, &anchor, directory, &options, out)?;
                out.data(json!({ "ids": ids, "anchor": anchor }), || ids.join("\n"));
                if let Some(id) = ids.first() {
                    out.progress(&format!(
                        "hint: run `guac credential issue --moderator <name> --endorsement {id}`"
                    ));
                }
            }
            EndorsementCommand::List => {
                let rows = store.endorsements()?;
                out.data(
                    json!(rows.iter().map(|e| json!({ "id": e.id, "anchor": e.anchor, "created_at": e.created_at })).collect::<Vec<_>>()),
                    || table(rows.iter().map(|e| vec![e.id.clone(), e.anchor.clone(), age(e.created_at)]).collect()),
                );
            }
            EndorsementCommand::Show { id } => {
                let e = store.endorsement(&id)?;
                out.data(
                    json!({ "id": e.id, "anchor": e.anchor, "created_at": e.created_at, "anchor_key": http::encode(&e.directory.anchor.key) }),
                    || format!("id: {}\nanchor: {}\ncreated: {}\nanchor key: {}", e.id, e.anchor, age(e.created_at), http::encode(&e.directory.anchor.key)),
                );
            }
            EndorsementCommand::Remove { id, force } => {
                let e = store.endorsement(&id)?;
                confirm(
                    &format!("Delete unused endorsement `{id}`?"),
                    force,
                    cli.no_input,
                )?;
                store.transition(Some(Take::Endorsement(&e)), None)?;
                out.progress(&format!("Deleted `{id}`."));
            }
        },
        Command::Credential(command) => match command {
            CredentialCommand::Issue {
                moderator,
                endorsement,
                name,
            } => {
                let saved: ModeratorDirectory = store.remote(Kind::Moderator, &moderator)?;
                let directory = remote::fetch_moderator(&saved.url, saved.access)?;
                store.put_remote(Kind::Moderator, &moderator, &directory, true)?;
                let endorsement = endorsement.map(|id| store.endorsement(&id)).transpose()?;
                let name = name.unwrap_or_else(|| moderator.clone());
                let c = issue::issue(
                    &mut store,
                    &moderator,
                    directory,
                    endorsement.as_ref(),
                    &name,
                    out,
                )?;
                out.data(
                    json!({ "name": c.name, "moderator": c.moderator, "balance": c.balance }),
                    || format!("{}: {} credits", c.name, c.balance),
                );
            }
            CredentialCommand::List => {
                let rows = store.credentials()?;
                out.data(
                    json!(rows.iter().map(|c| json!({ "name": c.name, "moderator": c.moderator, "balance": c.balance })).collect::<Vec<_>>()),
                    || table(rows.iter().map(|c| vec![c.name.clone(), c.moderator.clone(), format!("{} credits", c.balance)]).collect()),
                );
            }
            CredentialCommand::Show { name } => {
                let c = store.credential(&name)?;
                out.data(
                    json!({ "name": c.name, "moderator": c.moderator, "balance": c.balance, "issuance_uri": c.directory.issuance_uri, "created_at": c.created_at }),
                    || format!("name: {}\nmoderator: {}\nbalance: {} credits\nissuer: {}\nupdated: {}", c.name, c.moderator, c.balance, c.directory.issuance_uri, age(c.created_at)),
                );
            }
            CredentialCommand::Rename { old, new } => {
                store.rename_credential(&old, &new)?;
                out.progress(&format!("Renamed `{old}` to `{new}`."));
            }
            CredentialCommand::Remove { name, force } => {
                let c = store.credential(&name)?;
                confirm(
                    &format!("Delete `{name}` and its {} credits?", c.balance),
                    force,
                    cli.no_input,
                )?;
                store.transition(Some(Take::Credential(&c)), None)?;
                out.progress(&format!("Deleted `{name}`."));
            }
        },
        Command::Curl(args) => {
            if cli.json {
                bail!("--json does not apply to guac curl; its output is the response body");
            }
            return curl::run(&mut store, &args.credential, args.max_cost, &args.args, out);
        }
        Command::Pending(command) => match command {
            PendingCommand::List => {
                let rows = store.pendings()?;
                out.data(
                    json!(rows.iter().map(pending_json).collect::<Vec<_>>()),
                    || {
                        table(
                            rows.iter()
                                .map(|p| {
                                    vec![
                                        p.id.clone(),
                                        p.record.kind().to_owned(),
                                        p.record.subject().to_owned(),
                                        age(p.created_at),
                                    ]
                                })
                                .collect(),
                        )
                    },
                );
            }
            PendingCommand::Show { id } => {
                let row = store.pending(&id)?;
                let value = pending_json(&row);
                out.data(value.clone(), || {
                    let mut lines: Vec<String> = value
                        .as_object()
                        .into_iter()
                        .flatten()
                        .filter(|(k, _)| *k != "created_at")
                        .map(|(k, v)| {
                            format!(
                                "{k}: {}",
                                v.as_str().map_or_else(|| v.to_string(), str::to_owned)
                            )
                        })
                        .collect();
                    lines.push(format!("started: {}", age(row.created_at)));
                    lines.push(format!(
                        "hint: `guac pending retry {id}` resends the saved request unchanged"
                    ));
                    lines.join("\n")
                });
            }
            PendingCommand::Retry { id } => {
                let row = store.pending(&id)?;
                match row.record {
                    Pending::Grant { .. } => {
                        let ids = grant::finish(&mut store, &id)?;
                        out.data(json!({ "ids": ids }), || ids.join("\n"));
                    }
                    Pending::Issuance { .. } => {
                        let c = issue::finish(&mut store, &id)?;
                        out.data(json!({ "name": c.name, "balance": c.balance }), || {
                            format!("{}: {} credits", c.name, c.balance)
                        });
                    }
                    Pending::Presentation { .. } => return curl::send(&mut store, &id, out),
                }
            }
            PendingCommand::Recover { id } => {
                curl::recover(&mut store, &id, out)?;
                out.progress("The request's response is unavailable; it was not repeated.");
            }
            PendingCommand::Forget { id, force } => {
                let row = store.pending(&id)?;
                let loss = match &row.record {
                    Pending::Grant { .. } => "the grant in progress".to_owned(),
                    Pending::Issuance { credential, .. } => {
                        format!("the redeemed endorsement for `{credential}`")
                    }
                    Pending::Presentation { credential, .. } => {
                        format!("all remaining credits of `{credential}`")
                    }
                };
                confirm(
                    &format!("Forget `{id}`? This discards {loss}; it cannot be recovered."),
                    force,
                    cli.no_input,
                )?;
                store.transition(Some(Take::Pending(&id)), None)?;
                out.progress(&format!("Forgot `{id}`."));
            }
        },
        Command::Status => {
            let (endorsements, credentials, pending) = (
                store.endorsements()?,
                store.credentials()?,
                store.pendings()?,
            );
            out.data(
                json!({
                    "endorsements": endorsements.iter().map(|e| json!({ "id": e.id, "anchor": e.anchor })).collect::<Vec<_>>(),
                    "credentials": credentials.iter().map(|c| json!({ "name": c.name, "moderator": c.moderator, "balance": c.balance })).collect::<Vec<_>>(),
                    "pending": pending.iter().map(pending_json).collect::<Vec<_>>(),
                }),
                || {
                    let section = |title: &str, rows: Vec<Vec<String>>| {
                        if rows.is_empty() { format!("{title}\n(none)") } else { format!("{title}\n{}", table(rows)) }
                    };
                    let mut text = [
                        section("ENDORSEMENTS", endorsements.iter().map(|e| vec![e.id.clone(), e.anchor.clone(), age(e.created_at)]).collect()),
                        section("CREDENTIALS", credentials.iter().map(|c| vec![c.name.clone(), c.moderator.clone(), format!("{} credits", c.balance)]).collect()),
                        section("PENDING", pending.iter().map(|p| vec![p.id.clone(), p.record.kind().to_owned(), p.record.subject().to_owned(), age(p.created_at)]).collect()),
                    ]
                    .join("\n\n");
                    if let Some(p) = pending.first() {
                        text.push_str(&format!("\n\nRun: guac pending show {}", p.id));
                    }
                    text
                },
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}
