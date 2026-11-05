//! Local state: one SQLite database, private to the user.
//!
//! Invariant: secret material is usable *or* pending, never both. Every
//! transition deletes exactly the row it consumes (matching its secret bytes,
//! so a concurrent process cannot spend the same state) and inserts its
//! successor in one IMMEDIATE transaction. Nothing is sent before it commits.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{
    curl::SavedRequest,
    remote::{AnchorDirectory, ModeratorDirectory},
};

pub type Secret = Zeroizing<Vec<u8>>;

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Anchor,
    Moderator,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Anchor => "anchor",
            Self::Moderator => "moderator",
        }
    }
}

/// Public parts of an interrupted exchange; its secret is stored beside it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Pending {
    /// Between the two Anchor exchanges. `request` is the exact second request.
    Grant {
        anchor: String,
        directory: AnchorDirectory,
        route: String,
        /// PKCE verifier binding a browser-approved grant session.
        verifier: Option<String>,
        request: Vec<u8>,
    },
    /// Endorsement redeemed; awaiting the issuance response.
    Issuance {
        credential: String,
        moderator: String,
        directory: ModeratorDirectory,
        authorization: String,
    },
    /// Credential presented; awaiting the credential update.
    Presentation {
        credential: String,
        moderator: String,
        directory: ModeratorDirectory,
        cost: u64,
        authorization: String,
        request: SavedRequest,
    },
}

impl Pending {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Grant { .. } => "grant",
            Self::Issuance { .. } => "issuance",
            Self::Presentation { .. } => "presentation",
        }
    }

    /// The credential name this exchange will produce or replace.
    pub fn credential(&self) -> Option<&str> {
        match self {
            Self::Grant { .. } => None,
            Self::Issuance { credential, .. } | Self::Presentation { credential, .. } => {
                Some(credential)
            }
        }
    }

    pub fn subject(&self) -> &str {
        match self {
            Self::Grant { anchor, .. } => anchor,
            Self::Issuance { credential, .. } | Self::Presentation { credential, .. } => credential,
        }
    }
}

pub struct Endorsement {
    pub id: String,
    pub anchor: String,
    pub directory: AnchorDirectory,
    pub secret: Secret,
    pub created_at: i64,
}

pub struct Credential {
    pub name: String,
    pub moderator: String,
    pub directory: ModeratorDirectory,
    pub secret: Secret,
    pub balance: u64,
    pub created_at: i64,
}

pub struct PendingRow {
    pub id: String,
    pub record: Pending,
    pub secret: Secret,
    pub created_at: i64,
}

/// The state a transition consumes. Secrets must match what was loaded.
pub enum Take<'a> {
    Endorsement(&'a Endorsement),
    Credential(&'a Credential),
    Pending(&'a str),
}

/// The state a transition produces.
pub enum Put<'a> {
    Endorsements(&'a [Endorsement]),
    Credential(&'a Credential),
    Pending(&'a PendingRow),
}

pub struct Store {
    conn: Connection,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `GUAC_HOME`, else the platform data directory (e.g. ~/.local/share/guac).
pub fn home() -> Result<PathBuf> {
    match std::env::var_os("GUAC_HOME") {
        Some(path) => Ok(path.into()),
        None => Ok(dirs::data_dir()
            .context("no data directory; set GUAC_HOME")?
            .join("guac")),
    }
}

fn json<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

fn parse<T: DeserializeOwned>(text: &str) -> Result<T> {
    serde_json::from_str(text).context("corrupt local state record")
}

impl Store {
    pub fn open() -> Result<Self> {
        let home = home()?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(&home)
            .with_context(|| format!("cannot create {}", home.display()))?;
        let path = home.join("guac.sqlite3");
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(
            std::fs::OpenOptions::new().append(true).create(true),
            0o600,
        )
        .open(&path)
        .with_context(|| format!("cannot create {}", path.display()))?;
        let conn =
            Connection::open(&path).with_context(|| format!("cannot open {}", path.display()))?;
        #[cfg(unix)]
        for suffix in ["", "-wal", "-shm"] {
            use std::os::unix::fs::PermissionsExt;
            let mut file = path.as_os_str().to_os_string();
            file.push(suffix);
            let file = PathBuf::from(file);
            if file.exists() {
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA secure_delete = ON;
             CREATE TABLE IF NOT EXISTS remotes (kind TEXT NOT NULL, name TEXT NOT NULL,
               directory TEXT NOT NULL, PRIMARY KEY (kind, name));
             CREATE TABLE IF NOT EXISTS endorsements (id TEXT PRIMARY KEY, anchor TEXT NOT NULL,
               directory TEXT NOT NULL, secret BLOB NOT NULL, created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS credentials (name TEXT PRIMARY KEY, moderator TEXT NOT NULL,
               directory TEXT NOT NULL, secret BLOB NOT NULL, balance INTEGER NOT NULL,
               created_at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, credential TEXT UNIQUE,
               record TEXT NOT NULL, secret BLOB NOT NULL, created_at INTEGER NOT NULL);",
        )?;
        Ok(Self { conn })
    }

    // --- Remotes (public configuration) ---

    pub fn put_remote<T: Serialize>(
        &self,
        kind: Kind,
        name: &str,
        directory: &T,
        replace: bool,
    ) -> Result<()> {
        let sql = if replace {
            "INSERT OR REPLACE INTO remotes VALUES (?1, ?2, ?3)"
        } else {
            "INSERT INTO remotes VALUES (?1, ?2, ?3)"
        };
        match self
            .conn
            .execute(sql, params![kind.as_str(), name, json(directory)?])
        {
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                bail!("{} `{name}` already exists", kind.as_str())
            }
            result => Ok(result.map(drop)?),
        }
    }

    pub fn remote<T: DeserializeOwned>(&self, kind: Kind, name: &str) -> Result<T> {
        let text: Option<String> = self
            .conn
            .query_row(
                "SELECT directory FROM remotes WHERE kind = ?1 AND name = ?2",
                params![kind.as_str(), name],
                |row| row.get(0),
            )
            .optional()?;
        match text {
            Some(text) => parse(&text),
            None => bail!(
                "no {} named `{name}`\nhint: run `guac {} list`",
                kind.as_str(),
                kind.as_str()
            ),
        }
    }

    pub fn remotes<T: DeserializeOwned>(&self, kind: Kind) -> Result<Vec<(String, T)>> {
        let mut statement = self
            .conn
            .prepare("SELECT name, directory FROM remotes WHERE kind = ?1 ORDER BY name")?;
        let rows = statement.query_map([kind.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (name, text) = row?;
            Ok((name, parse(&text)?))
        })
        .collect()
    }

    pub fn remove_remote(&self, kind: Kind, name: &str) -> Result<()> {
        if self.conn.execute(
            "DELETE FROM remotes WHERE kind = ?1 AND name = ?2",
            params![kind.as_str(), name],
        )? == 0
        {
            bail!("no {} named `{name}`", kind.as_str());
        }
        Ok(())
    }

    // --- Secret state ---

    pub fn endorsements(&self) -> Result<Vec<Endorsement>> {
        self.endorsements_where("1", [])
    }

    pub fn endorsement(&self, id: &str) -> Result<Endorsement> {
        self.endorsements_where("id = ?1", [id])?
            .pop()
            .with_context(|| format!("no endorsement `{id}`\nhint: run `guac endorsement list`"))
    }

    fn endorsements_where<P: rusqlite::Params>(
        &self,
        filter: &str,
        values: P,
    ) -> Result<Vec<Endorsement>> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT id, anchor, directory, secret, created_at FROM endorsements WHERE {filter} ORDER BY created_at, id"
        ))?;
        let rows = statement.query_map(values, |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get::<_, String>(2)?,
                Zeroizing::new(row.get(3)?),
                row.get(4)?,
            ))
        })?;
        rows.map(|row| {
            let (id, anchor, directory, secret, created_at) = row?;
            Ok(Endorsement {
                id,
                anchor,
                directory: parse(&directory)?,
                secret,
                created_at,
            })
        })
        .collect()
    }

    pub fn credentials(&self) -> Result<Vec<Credential>> {
        self.credentials_where("1", [])
    }

    pub fn credential(&self, name: &str) -> Result<Credential> {
        if let Some(pending) = self.pending_for(name)? {
            bail!(
                "credential `{name}` is pending ({})\nhint: run `guac pending show {}`",
                pending.record.kind(),
                pending.id
            );
        }
        self.credentials_where("name = ?1", [name])?
            .pop()
            .with_context(|| format!("no credential `{name}`\nhint: run `guac credential list`"))
    }

    fn credentials_where<P: rusqlite::Params>(
        &self,
        filter: &str,
        values: P,
    ) -> Result<Vec<Credential>> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT name, moderator, directory, secret, balance, created_at FROM credentials WHERE {filter} ORDER BY name"
        ))?;
        let rows = statement.query_map(values, |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get::<_, String>(2)?,
                Zeroizing::new(row.get(3)?),
                row.get::<_, i64>(4)?,
                row.get(5)?,
            ))
        })?;
        rows.map(|row| {
            let (name, moderator, directory, secret, balance, created_at) = row?;
            Ok(Credential {
                name,
                moderator,
                directory: parse(&directory)?,
                secret,
                balance: u64::try_from(balance).context("corrupt balance")?,
                created_at,
            })
        })
        .collect()
    }

    pub fn pendings(&self) -> Result<Vec<PendingRow>> {
        self.pending_where("1", [])
    }

    pub fn pending(&self, id: &str) -> Result<PendingRow> {
        self.pending_where("id = ?1", [id])?
            .pop()
            .with_context(|| format!("no pending exchange `{id}`\nhint: run `guac pending list`"))
    }

    fn pending_for(&self, credential: &str) -> Result<Option<PendingRow>> {
        Ok(self.pending_where("credential = ?1", [credential])?.pop())
    }

    fn pending_where<P: rusqlite::Params>(
        &self,
        filter: &str,
        values: P,
    ) -> Result<Vec<PendingRow>> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT id, record, secret, created_at FROM pending WHERE {filter} ORDER BY created_at, id"
        ))?;
        let rows = statement.query_map(values, |row| {
            Ok((
                row.get(0)?,
                row.get::<_, String>(1)?,
                Zeroizing::new(row.get(2)?),
                row.get(3)?,
            ))
        })?;
        rows.map(|row| {
            let (id, record, secret, created_at) = row?;
            Ok(PendingRow {
                id,
                record: parse(&record)?,
                secret,
                created_at,
            })
        })
        .collect()
    }

    /// Atomically consumes `take` and stores `put`. Fails, changing nothing,
    /// if `take` was already consumed (e.g. by another process) or `put`
    /// would reuse a credential name.
    pub fn transition(&mut self, take: Option<Take<'_>>, put: Option<Put<'_>>) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let taken = match &take {
            None => 1,
            Some(Take::Endorsement(e)) => tx.execute(
                "DELETE FROM endorsements WHERE id = ?1 AND secret = ?2",
                params![e.id, e.secret.as_slice()],
            )?,
            Some(Take::Credential(c)) => tx.execute(
                "DELETE FROM credentials WHERE name = ?1 AND secret = ?2",
                params![c.name, c.secret.as_slice()],
            )?,
            Some(Take::Pending(id)) => tx.execute("DELETE FROM pending WHERE id = ?1", [id])?,
        };
        if taken != 1 {
            bail!("local state changed concurrently (used by another guac process?)");
        }
        let taken_name: Option<&str> = match &take {
            Some(Take::Credential(c)) => Some(&c.name),
            _ => None,
        };
        let name_used = |name: &str| -> Result<bool> {
            Ok(tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM credentials WHERE name = ?1) OR EXISTS (SELECT 1 FROM pending WHERE credential = ?1)",
                [name],
                |row| row.get(0),
            )?)
        };
        match put {
            None => {}
            Some(Put::Endorsements(endorsements)) => {
                for e in endorsements {
                    tx.execute(
                        "INSERT INTO endorsements VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            e.id,
                            e.anchor,
                            json(&e.directory)?,
                            e.secret.as_slice(),
                            e.created_at
                        ],
                    )?;
                }
            }
            Some(Put::Credential(c)) => {
                if name_used(&c.name)? {
                    bail!("credential `{}` already exists", c.name);
                }
                tx.execute(
                    "INSERT INTO credentials VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        c.name,
                        c.moderator,
                        json(&c.directory)?,
                        c.secret.as_slice(),
                        i64::try_from(c.balance)?,
                        c.created_at
                    ],
                )?;
            }
            Some(Put::Pending(p)) => {
                if let Some(name) = p.record.credential()
                    && taken_name != Some(name)
                    && name_used(name)?
                {
                    bail!(
                        "credential `{name}` already exists\nhint: choose another name with --as"
                    );
                }
                tx.execute(
                    "INSERT INTO pending VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        p.id,
                        p.record.credential(),
                        json(&p.record)?,
                        p.secret.as_slice(),
                        p.created_at
                    ],
                )?;
            }
        }
        tx.commit().context("cannot commit local state")?;
        Ok(())
    }

    pub fn rename_credential(&mut self, old: &str, new: &str) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let used: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM credentials WHERE name = ?1) OR EXISTS (SELECT 1 FROM pending WHERE credential = ?1)",
            [new],
            |row| row.get(0),
        )?;
        if used {
            bail!("credential `{new}` already exists");
        }
        if tx.execute(
            "UPDATE credentials SET name = ?2 WHERE name = ?1",
            [old, new],
        )? != 1
        {
            bail!("no usable credential `{old}`");
        }
        tx.commit()?;
        Ok(())
    }
}
