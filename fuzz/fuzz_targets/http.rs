#![no_main]

use guac::http::{Authorization, Challenge, CredentialField};
use libfuzzer_sys::fuzz_target;

// Header field values reach these parsers unauthenticated. What parses must
// print back to something that parses to the same value.
fuzz_target!(|bytes: &[u8]| {
    let Ok(field) = std::str::from_utf8(bytes) else {
        return;
    };

    if let Ok(Some(authorization)) = Authorization::parse(field) {
        let printed = authorization.to_string();
        assert_eq!(
            Authorization::parse(&printed).ok(),
            Some(Some(authorization))
        );
    }

    for challenge in Challenge::parse([field]) {
        let printed = challenge.to_string();
        assert_eq!(Challenge::parse([printed.as_str()]), [challenge]);
    }

    if let Ok(Some(credential)) = CredentialField::parse([field]) {
        let printed = credential.to_string();
        assert_eq!(
            CredentialField::parse([printed.as_str()]).ok(),
            Some(Some(credential))
        );
    }
});
