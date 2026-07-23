use std::collections::HashSet;

use hex::decode;
use serde::Deserialize;

use prometheus_threat_hint::{ObservableBundle, ObservableBundleError};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestBundleVectors {
    vector_schema_version: u8,
    valid_cases: Vec<ValidCase>,
    invalid_bundle_cases: Vec<InvalidBundleCase>,
    invalid_commitment_cases: Vec<InvalidCommitmentCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidCase {
    name: String,
    wire_hex: String,
    network_id: String,
    report_nonce_hex: String,
    commitment_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvalidBundleCase {
    name: String,
    wire_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvalidCommitmentCase {
    name: String,
    wire_hex: String,
    network_id: String,
    report_nonce_hex: String,
}

fn vectors() -> TestBundleVectors {
    serde_json::from_str(include_str!("vectors/threat-observable-bundle-v1.json"))
        .expect("valid fixture")
}

#[test]
fn fixture_rejects_unknown_fields() {
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("vectors/threat-observable-bundle-v1.json"))
            .expect("valid fixture");

    let mut top_level = raw.clone();
    top_level
        .as_object_mut()
        .expect("top-level object")
        .insert("unexpected_case".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<TestBundleVectors>(top_level).is_err());

    for group in [
        "valid_cases",
        "invalid_bundle_cases",
        "invalid_commitment_cases",
    ] {
        let mut with_case_field = raw.clone();
        let first = with_case_field
            .get_mut(group)
            .and_then(|value| value.as_array_mut())
            .and_then(|cases| cases.first_mut())
            .and_then(|value| value.as_object_mut())
            .unwrap_or_else(|| panic!("{group} must contain an object"));
        first.insert("unexpected_case_field".to_string(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<TestBundleVectors>(with_case_field).is_err(),
            "{group} case accepted an unknown field"
        );
    }
}

#[test]
fn fixtures_have_unique_case_names() {
    let fixtures = vectors();

    assert_eq!(fixtures.vector_schema_version, 1);

    let mut names = HashSet::new();
    let case_count = fixtures.valid_cases.len()
        + fixtures.invalid_bundle_cases.len()
        + fixtures.invalid_commitment_cases.len();
    names.reserve(case_count);

    for case in fixtures
        .valid_cases
        .iter()
        .map(|case| &case.name)
        .chain(fixtures.invalid_bundle_cases.iter().map(|case| &case.name))
        .chain(
            fixtures
                .invalid_commitment_cases
                .iter()
                .map(|case| &case.name),
        )
    {
        assert!(names.insert(case), "duplicate case name: {case}");
    }
}

#[test]
fn valid_cases_roundtrip_and_commitment() {
    let fixtures = vectors();
    assert!(fixtures.valid_cases.len() >= 5);

    for case in fixtures.valid_cases {
        let wire = decode(&case.wire_hex).expect("valid wire hex");
        let bundle = ObservableBundle::parse_canonical(&wire)
            .unwrap_or_else(|error| panic!("{name} failed parse: {error}", name = case.name));
        assert_eq!(bundle.to_canonical_bytes().expect("canonical bytes"), wire);

        let commitment = bundle
            .commitment(&case.network_id, &case.report_nonce_hex)
            .expect("commitment");
        assert_eq!(hex::encode(commitment), case.commitment_hex);

        let expected = decode(case.commitment_hex).expect("expected commitment hex");
        assert!(ObservableBundle::commitment_matches(
            &expected,
            &case.network_id,
            &case.report_nonce_hex,
            &wire,
        )
        .expect("matching"));
    }
}

#[test]
fn invalid_bundle_vectors_rejected() {
    let fixtures = vectors();

    for case in fixtures.invalid_bundle_cases {
        let bytes = decode(case.wire_hex).expect("wire hex");
        assert!(
            ObservableBundle::parse_canonical(&bytes).is_err(),
            "{name} should be invalid",
            name = case.name
        );
    }
}

#[test]
fn invalid_commitment_contexts_rejected() {
    let fixtures = vectors();

    for case in fixtures.invalid_commitment_cases {
        let wire = decode(case.wire_hex).expect("wire hex");
        let bundle = ObservableBundle::parse_canonical(&wire).expect("valid wire");
        let err = bundle.commitment(&case.network_id, &case.report_nonce_hex);
        assert!(
            err.is_err(),
            "{name} should be invalid commitment context",
            name = case.name
        );
    }
}

#[test]
fn commitment_matching_rejects_mismatch_and_invalid_lengths() {
    let case = vectors()
        .valid_cases
        .into_iter()
        .next()
        .expect("valid case");
    let wire = decode(case.wire_hex).expect("wire hex");
    let mut mismatched = decode(case.commitment_hex).expect("commitment hex");
    mismatched[0] ^= 1;

    assert!(!ObservableBundle::commitment_matches(
        &mismatched,
        &case.network_id,
        &case.report_nonce_hex,
        &wire,
    )
    .expect("valid commitment comparison"));

    for invalid_expected in [&[0u8; 31][..], &[0u8; 33][..]] {
        assert!(matches!(
            ObservableBundle::commitment_matches(
                invalid_expected,
                &case.network_id,
                &case.report_nonce_hex,
                &wire,
            ),
            Err(ObservableBundleError::InvalidCommitment)
        ));
    }
}

#[test]
fn rejected_values_are_absent_from_error_text() {
    let rejected_value = "sensitive$observable";
    let wire = concat!(
        r#"{"schema_version":1,"disclosure_policy":"public_auto_v1","#,
        r#""scope":{"platform":"linux","format":"elf"},"#,
        r#""observables":[{"kind":"api_import","value":"$VALUE"}]}"#
    )
    .replace("$VALUE", rejected_value);
    let error = match ObservableBundle::parse_canonical(wire.as_bytes()) {
        Ok(_) => panic!("invalid observable was accepted"),
        Err(error) => error,
    };

    assert!(matches!(error, ObservableBundleError::InvalidObservable));
    assert!(!error.to_string().contains(rejected_value));
    assert!(!format!("{error:?}").contains(rejected_value));
}

#[test]
fn rejects_byte_pattern_over_token_cap() {
    let value = vec!["aa"; 65].join(" ");
    let wire = concat!(
        r#"{"schema_version":1,"disclosure_policy":"review_required_v1","#,
        r#""scope":{"platform":"linux","format":"elf"},"#,
        r#""observables":[{"kind":"byte_pattern","value":"$VALUE"}]}"#
    )
    .replace("$VALUE", &value);

    assert!(matches!(
        ObservableBundle::parse_canonical(wire.as_bytes()),
        Err(ObservableBundleError::InvalidObservable)
    ));
}

#[test]
fn rejects_noncanonical_wire_over_cap() {
    let oversized = vec![b'{'; 4097];
    let result = ObservableBundle::parse_canonical(&oversized);
    assert!(matches!(result, Err(ObservableBundleError::BundleTooLarge)));
}
