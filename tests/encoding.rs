use guac::{
    Error,
    http::{Authorization, Challenge, CredentialField, ENDORSEMENT_RESPONSE, check_content_type},
    protocol::{
        CredentialChallenge, CredentialPresentation, CredentialRequest, CredentialUpdate,
        ModeratorChallenge,
    },
};

#[test]
fn hand_written_encodings() {
    let challenge = ModeratorChallenge::from_parts(2, &[0; 32]).unwrap();
    assert_eq!(
        Challenge::Redeem(challenge).to_string(),
        "Mole redeem-0002=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\""
    );
    // cost=2, allowance=1, context="e", empty request context.
    let bytes = hex::decode("00000000000000020000000000000001016500").unwrap();
    let challenge = CredentialChallenge::from_bytes(&bytes).unwrap();
    assert_eq!((challenge.cost(), challenge.allowance()), (2, 1));
    assert_eq!(challenge.to_bytes(), bytes);
    // An empty update is a recorded NoUpdate.
    let field = CredentialField::Update(CredentialUpdate::from_bytes(&[]).unwrap());
    assert_eq!(field.to_string(), "update-0001=\"\"");
    assert_eq!(
        CredentialField::parse(["update-0001=\"\""]).unwrap(),
        Some(field)
    );
    assert_eq!(CredentialField::parse([]).unwrap(), None);
    let request = CredentialRequest::from_parts(1, &[], &[1, 2]).unwrap();
    let header = Authorization::Issue(request.clone()).to_string();
    assert_eq!(
        header,
        "Mole redeem-0001=\"\", credential-request-0001=\"AQI\""
    );
    assert_eq!(
        Authorization::parse(&header).unwrap(),
        Some(Authorization::Issue(request))
    );
}

#[test]
fn challenge_fields() {
    let redeem = format!("redeem-0002=\"{}\"", "A".repeat(43));
    // Several challenges in one field, quoted-pair escapes, other schemes.
    let field = format!("Basic realm=\"a\\\"b\", Mole {redeem}, Mole endorse-0002=\"\"");
    let parsed = Challenge::parse([field.as_str()]);
    assert!(matches!(
        parsed.as_slice(),
        [Challenge::Redeem(_), Challenge::Endorse]
    ));
    // Unknown types and unreserved parameters are skipped or ignored.
    assert_eq!(
        Challenge::parse(["Mole endorse-0003=\"\"", "Mole x=1, endorse-0002=\"\""]),
        [Challenge::Endorse]
    );
    for bad in [
        // Duplicate (case-insensitive) names.
        format!("Mole {redeem}, REDEEM-0002=\"{}\"", "A".repeat(43)),
        // Padding and noncanonical trailing bits.
        format!("Mole redeem-0002=\"{}=\"", "A".repeat(43)),
        format!("Mole redeem-0002=\"{}B\"", "A".repeat(42)),
        // Reserved prefix with a malformed type.
        "Mole endorse-002=\"\"".into(),
        "Mole endorse-0000=\"\"".into(),
        // Two payloads in one challenge.
        format!("Mole {redeem}, endorse-0002=\"\""),
    ] {
        assert!(Challenge::parse([bad.as_str()]).is_empty(), "{bad}");
    }
    // A syntax error ends the field; earlier challenges stay usable.
    assert_eq!(
        Challenge::parse(["Mole endorse-0002=\"\", Mole x=@"]),
        [Challenge::Endorse]
    );
}

#[test]
fn authorization_fields() {
    assert_eq!(Authorization::parse("Bearer x").unwrap(), None);
    assert!(matches!(
        Authorization::parse("Mole presentation-0002=\"AA\""),
        Err(Error::Unsupported(2))
    ));
    for bad in [
        "Mole",
        "Mole presentation-0001=\"AA\", presentation-0001=\"AA\"",
        "Mole presentation-0001=\"AA\", Mole presentation-0001=\"AA\"",
        "Mole redeem-0001=\"AA\", credential-request-0001=\"AA\"",
        "Mole recovery-0001=\"AA\"",
    ] {
        assert!(Authorization::parse(bad).is_err(), "{bad}");
    }
    assert!(CredentialField::parse(["update-0001=\"\"", "update-0001=\"\""]).is_err());
    assert!(CredentialField::parse(["update-0001=\"\", x=1"]).is_err());
}

#[test]
fn many_unknown_parameters_still_reject_case_insensitive_duplicates() {
    let mut field = String::from("Mole presentation-0001=\"AA\"");
    for i in 0..20_000 {
        field.push_str(&format!(", x{i}=\"\""));
    }
    assert!(matches!(
        Authorization::parse(&field),
        Ok(Some(Authorization::Present(_)))
    ));
    field.push_str(", X19999=\"different\"");
    assert!(matches!(
        Authorization::parse(&field),
        Err(Error::Malformed)
    ));
}

#[test]
fn strict_payload_parsing() {
    assert!(matches!(
        ModeratorChallenge::from_parts(3, &[0; 32]),
        Err(Error::Unsupported(3))
    ));
    assert!(matches!(
        ModeratorChallenge::from_parts(0, &[0; 32]),
        Err(Error::Malformed)
    ));
    assert!(ModeratorChallenge::from_parts(2, &[0; 31]).is_err());
    for bytes in [&[][..], &[0; 17][..], &[0; 19][..]] {
        assert!(CredentialChallenge::from_bytes(bytes).is_err());
    }
    assert!(CredentialUpdate::from_bytes(&vec![0; guac::protocol::MAX_MESSAGE_BYTES + 1]).is_err());
    let mut body = vec![7; 32];
    body.push(1);
    let presentation = CredentialPresentation::from_bytes(&body).unwrap();
    assert_eq!(presentation.key_id(), Some([7; 32]));
    assert_eq!(
        CredentialPresentation::from_bytes(&[7; 31])
            .unwrap()
            .key_id(),
        None
    );
}

#[test]
fn moderator_endpoint_requires_https_or_loopback_http() {
    let key = guac::Moderator::generate(
        "https://moderator.example/",
        4,
        b"c".to_vec(),
        guac::EndorsementPolicy::NotRequired,
        60,
    )
    .unwrap()
    .configuration()
    .public_key();
    let config = |endpoint| {
        guac::ModeratorConfig::new(
            endpoint,
            &key,
            4,
            b"c".to_vec(),
            guac::EndorsementPolicy::NotRequired,
            60,
        )
    };
    for ok in [
        "https://m.example/issue",
        "http://127.0.0.1:8787/issue",
        "http://localhost/issue",
        "http://[::1]/issue",
    ] {
        assert!(config(ok).is_ok(), "{ok}");
    }
    let anchor = guac::Anchor::generate(b"epoch".to_vec()).unwrap();
    let policy = guac::EndorsementPolicy::Required(
        guac::AnchorSet::new(&[anchor.configuration().clone()]).unwrap(),
    );
    for endpoint in [
        "https://127.0.0.1/",
        "http://[::1]/",
        "https://my_moderator.example/",
    ] {
        assert!(matches!(
            guac::ModeratorConfig::new(endpoint, &key, 4, vec![], policy.clone(), 60),
            Err(Error::Configuration(_))
        ));
    }
    let idn =
        guac::ModeratorConfig::new("https://bücher.example/", &key, 4, vec![], policy, 60).unwrap();
    assert_eq!(
        idn.redemption_scope().unwrap().moderator_domain(),
        "xn--bcher-kva.example"
    );
    for bad in [
        "http://m.example/issue",
        "http://127.0.0.1.example/",
        "ftp://127.0.0.1/",
    ] {
        assert!(config(bad).is_err(), "{bad}");
    }
}

#[test]
fn content_type_parameters() {
    let check = |value| check_content_type(value, ENDORSEMENT_RESPONSE);
    check(ENDORSEMENT_RESPONSE).unwrap();
    check("Application/Mole-Endorsement-Response ; x=\"a;b\\\"\";TYPE=\"0002\"").unwrap();
    // A `type=` inside a quoted value is not a parameter.
    assert!(matches!(
        check("application/mole-endorsement-response; x=\"a;type=0002\""),
        Err(Error::Mismatch)
    ));
    assert!(matches!(
        check("application/mole-endorsement-response; type=0002; type=0002"),
        Err(Error::Mismatch)
    ));
    assert!(matches!(
        check("application/mole-endorsement-response; type=\"0002"),
        Err(Error::Malformed)
    ));
}

#[test]
fn scoped_secret_envelopes() {
    let anchor = guac::Anchor::generate(b"epoch".to_vec()).unwrap();
    let scope = guac::RedemptionScope::for_moderator_domain("moderator.example").unwrap();
    let (_, pending) =
        guac::Client.start_grant(anchor.configuration(), std::num::NonZeroU16::MIN, &scope);
    let mut bytes = pending.to_storage_bytes();
    assert_eq!(&bytes[..8], b"GUAC\x02\x07\x00\x02");
    assert_eq!(&bytes[40..], b"\x15\x11moderator.example\x00\x00\x01");
    bytes[5] = 5;
    assert!(matches!(
        guac::PendingGrant::from_storage_bytes(&bytes, anchor.configuration()),
        Err(Error::Malformed)
    ));
}
