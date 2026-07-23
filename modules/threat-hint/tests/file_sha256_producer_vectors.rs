use std::collections::HashSet;

use hex::decode;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use prometheus_threat_hint::{
    produce_file_sha256_bundle, DisclosurePolicy, ObservableBundle, ObservableKind, ScopeFormat,
    ScopePlatform,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerVectors {
    vector_schema_version: u8,
    cases: Vec<ProducerCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerCase {
    name: String,
    artifact_hex: String,
    platform: ScopePlatform,
    format: ScopeFormat,
    file_sha256: String,
    wire_hex: String,
}

fn vectors() -> ProducerVectors {
    serde_json::from_str(include_str!(
        "vectors/threat-observable-file-sha256-producer-v1.json"
    ))
    .expect("valid producer fixture")
}

#[test]
fn fixture_schema_and_case_names_are_unique() {
    let fixtures = vectors();
    assert_eq!(fixtures.vector_schema_version, 1);
    assert!(fixtures.cases.len() >= 3);

    let mut names = HashSet::with_capacity(fixtures.cases.len());
    for case in fixtures.cases {
        assert!(names.insert(case.name), "duplicate producer case name");
    }
}

#[test]
fn exact_artifact_bytes_produce_expected_canonical_bundle() {
    for case in vectors().cases {
        let artifact = decode(&case.artifact_hex).expect("artifact hex");
        let expected_wire = decode(&case.wire_hex).expect("wire hex");
        let expected_digest = Sha256::digest(&artifact);

        assert_eq!(hex::encode(&artifact), case.artifact_hex);
        assert_eq!(hex::encode(&expected_wire), case.wire_hex);
        assert_eq!(hex::encode(expected_digest), case.file_sha256);

        let bundle = produce_file_sha256_bundle(&artifact, case.platform, case.format)
            .unwrap_or_else(|error| panic!("{} failed production: {error}", case.name));
        assert_eq!(bundle.disclosure_policy(), DisclosurePolicy::PublicAutoV1);
        assert_eq!(bundle.scope().platform(), case.platform);
        assert_eq!(bundle.scope().format(), case.format);
        assert_eq!(bundle.observables().len(), 1);
        assert_eq!(bundle.observables()[0].kind(), ObservableKind::FileSha256);
        assert_eq!(bundle.observables()[0].value(), case.file_sha256);
        assert_eq!(
            bundle.to_canonical_bytes().expect("canonical bytes"),
            expected_wire
        );

        let reparsed =
            ObservableBundle::parse_canonical(&expected_wire).expect("valid expected wire");
        assert_eq!(reparsed.observables()[0].value(), case.file_sha256);
    }
}

#[test]
fn changing_one_artifact_bit_changes_digest_and_wire() {
    let first = produce_file_sha256_bundle(&[0], ScopePlatform::Any, ScopeFormat::Unknown)
        .expect("first bundle");
    let second = produce_file_sha256_bundle(&[1], ScopePlatform::Any, ScopeFormat::Unknown)
        .expect("second bundle");

    assert_ne!(
        first.observables()[0].value(),
        second.observables()[0].value()
    );
    assert_ne!(
        first.to_canonical_bytes().expect("first wire"),
        second.to_canonical_bytes().expect("second wire")
    );
}
