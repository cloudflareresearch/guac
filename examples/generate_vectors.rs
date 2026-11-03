//! Captures randomized protocol transcripts in tests/vectors/transcripts.json.

#[path = "../tests/support/mod.rs"]
mod support;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use guac::UpdatePolicy::{Consume, ReturnCredits};
    let corpus = support::Corpus {
        version: 2,
        draft: "draft-jms-mole-protocols and draft-jms-mole-http-transport, PR #138 (d68ef1bf)"
            .into(),
        act_revision: support::ACT_REV.into(),
        ihat_revision: support::IHAT_REV.into(),
        generation: "captured OS-random transcripts; not deterministic regeneration".into(),
        cases: vec![
            support::capture("anchor-0", Some(0), ReturnCredits(1))?,
            support::capture("anchor-1", Some(1), ReturnCredits(1))?,
            support::capture("unendorsed", None, ReturnCredits(1))?,
            support::capture("consumed", None, Consume)?,
        ],
    };
    std::fs::write(
        "tests/vectors/transcripts.json",
        format!("{}\n", serde_json::to_string_pretty(&corpus)?),
    )?;
    Ok(())
}
