use std::collections::HashSet;

use hex::decode;
use serde::Deserialize;

use prometheus_threat_hint::{
    produce_byte_pattern_bundle, DisclosurePolicy, ObservableBundle, ObservableBundleError,
    ObservableKind, ScopeFormat, ScopePlatform,
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
    start: usize,
    wildcard_mask: Vec<bool>,
    platform: ScopePlatform,
    format: ScopeFormat,
    byte_pattern: String,
    wire_hex: String,
}

fn vectors() -> ProducerVectors {
    serde_json::from_str(include_str!(
        "vectors/threat-observable-byte-pattern-producer-v1.json"
    ))
    .expect("valid producer fixture")
}

fn expected_pattern(artifact: &[u8], start: usize, wildcard_mask: &[bool]) -> String {
    artifact[start..start + wildcard_mask.len()]
        .iter()
        .zip(wildcard_mask)
        .map(|(&byte, &wildcard)| {
            if wildcard {
                "??".to_owned()
            } else {
                hex::encode([byte])
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn fixture_schema_and_case_names_are_unique() {
    let fixtures = vectors();
    assert_eq!(fixtures.vector_schema_version, 1);
    assert!(fixtures.cases.len() >= 3);

    let mut names = HashSet::with_capacity(fixtures.cases.len());
    for case in fixtures.cases {
        assert!(names.insert(case.name), "duplicate producer case name");
        assert!((8..=64).contains(&case.wildcard_mask.len()));
        assert!(
            case.wildcard_mask
                .iter()
                .filter(|wildcard| !**wildcard)
                .count()
                >= 8
        );
    }
}

#[test]
fn exact_artifact_selection_produces_expected_review_required_bundle() {
    for case in vectors().cases {
        let artifact = decode(&case.artifact_hex).expect("artifact hex");
        let expected_wire = decode(&case.wire_hex).expect("wire hex");

        assert_eq!(hex::encode(&artifact), case.artifact_hex);
        assert_eq!(hex::encode(&expected_wire), case.wire_hex);
        assert_eq!(
            expected_pattern(&artifact, case.start, &case.wildcard_mask),
            case.byte_pattern
        );

        let bundle = produce_byte_pattern_bundle(
            &artifact,
            case.start,
            &case.wildcard_mask,
            case.platform,
            case.format,
        )
        .unwrap_or_else(|error| panic!("{} failed production: {error}", case.name));
        assert_eq!(
            bundle.disclosure_policy(),
            DisclosurePolicy::ReviewRequiredV1
        );
        assert_eq!(bundle.scope().platform(), case.platform);
        assert_eq!(bundle.scope().format(), case.format);
        assert_eq!(bundle.observables().len(), 1);
        assert_eq!(bundle.observables()[0].kind(), ObservableKind::BytePattern);
        assert_eq!(bundle.observables()[0].value(), case.byte_pattern);
        assert_eq!(
            bundle.to_canonical_bytes().expect("canonical bytes"),
            expected_wire
        );

        let reparsed =
            ObservableBundle::parse_canonical(&expected_wire).expect("valid expected wire");
        assert_eq!(
            reparsed.disclosure_policy(),
            DisclosurePolicy::ReviewRequiredV1
        );
        assert_eq!(reparsed.observables()[0].value(), case.byte_pattern);
    }
}

#[test]
fn invalid_lengths_fixed_count_and_ranges_fail_closed() {
    let artifact = [0u8; 80];
    let invalid_masks = [
        Vec::new(),
        vec![false; 7],
        vec![false; 65],
        vec![true, false, false, false, false, false, false, false],
    ];

    for mask in invalid_masks {
        assert!(matches!(
            produce_byte_pattern_bundle(
                &artifact,
                0,
                &mask,
                ScopePlatform::Any,
                ScopeFormat::Unknown,
            ),
            Err(ObservableBundleError::InvalidObservable)
        ));
    }

    assert!(matches!(
        produce_byte_pattern_bundle(
            &artifact[..8],
            1,
            &[false; 8],
            ScopePlatform::Any,
            ScopeFormat::Unknown,
        ),
        Err(ObservableBundleError::InvalidObservable)
    ));
    assert!(matches!(
        produce_byte_pattern_bundle(
            &artifact[..8],
            artifact[..8].len(),
            &[false; 8],
            ScopePlatform::Any,
            ScopeFormat::Unknown,
        ),
        Err(ObservableBundleError::InvalidObservable)
    ));
    assert!(matches!(
        produce_byte_pattern_bundle(
            &artifact,
            usize::MAX,
            &[false; 8],
            ScopePlatform::Any,
            ScopeFormat::Unknown,
        ),
        Err(ObservableBundleError::InvalidObservable)
    ));
}

#[test]
fn upper_bound_pattern_is_accepted() {
    let artifact = [0xa5; 64];
    let bundle = produce_byte_pattern_bundle(
        &artifact,
        0,
        &[false; 64],
        ScopePlatform::Any,
        ScopeFormat::Unknown,
    )
    .expect("64 fixed bytes are valid");

    assert_eq!(
        bundle.observables()[0].value().split(' ').count(),
        artifact.len()
    );
}

#[test]
fn fixed_bytes_are_sensitive_and_wildcards_are_invariant() {
    let first_artifact = [0u8; 8];
    let mut changed_artifact = first_artifact;
    changed_artifact[0] = 1;

    let fixed_mask = [false; 8];
    let fixed_first = produce_byte_pattern_bundle(
        &first_artifact,
        0,
        &fixed_mask,
        ScopePlatform::Any,
        ScopeFormat::Unknown,
    )
    .expect("first fixed bundle");
    let fixed_changed = produce_byte_pattern_bundle(
        &changed_artifact,
        0,
        &fixed_mask,
        ScopePlatform::Any,
        ScopeFormat::Unknown,
    )
    .expect("changed fixed bundle");
    assert_ne!(
        fixed_first.to_canonical_bytes().expect("first fixed wire"),
        fixed_changed
            .to_canonical_bytes()
            .expect("changed fixed wire")
    );

    let wildcard_mask = [true, false, false, false, false, false, false, false, false];
    let first_with_extra = [0, 1, 2, 3, 4, 5, 6, 7, 8];
    let changed_with_extra = [1, 1, 2, 3, 4, 5, 6, 7, 8];
    let wildcard_first = produce_byte_pattern_bundle(
        &first_with_extra,
        0,
        &wildcard_mask,
        ScopePlatform::Any,
        ScopeFormat::Unknown,
    )
    .expect("first wildcard bundle");
    let wildcard_changed = produce_byte_pattern_bundle(
        &changed_with_extra,
        0,
        &wildcard_mask,
        ScopePlatform::Any,
        ScopeFormat::Unknown,
    )
    .expect("changed wildcard bundle");
    assert_eq!(
        wildcard_first
            .to_canonical_bytes()
            .expect("first wildcard wire"),
        wildcard_changed
            .to_canonical_bytes()
            .expect("changed wildcard wire")
    );
}
