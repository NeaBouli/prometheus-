use std::collections::HashSet;

use hex::decode;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use prometheus_threat_hint::{
    produce_elf_api_import_bundle, DisclosurePolicy, ObservableBundle, ObservableKind, ScopeFormat,
    ScopePlatform,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerVectors {
    vector_schema_version: u8,
    artifact_sha256: String,
    artifact_hex: String,
    cases: Vec<ProducerCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerCase {
    name: String,
    import_index: usize,
    api_import: String,
    wire_hex: String,
}

fn vectors() -> ProducerVectors {
    serde_json::from_str(include_str!(
        "vectors/threat-observable-elf-api-import-producer-v1.json"
    ))
    .expect("valid producer fixture")
}

#[test]
fn exact_elf_bytes_produce_expected_review_required_imports() {
    let fixtures = vectors();
    assert_eq!(fixtures.vector_schema_version, 1);
    assert!(fixtures.cases.len() >= 3);

    let artifact = decode(&fixtures.artifact_hex).expect("artifact hex");
    assert_eq!(hex::encode(&artifact), fixtures.artifact_hex);
    assert_eq!(
        hex::encode(Sha256::digest(&artifact)),
        fixtures.artifact_sha256
    );

    let mut names = HashSet::with_capacity(fixtures.cases.len());
    for case in fixtures.cases {
        assert!(
            names.insert(case.name.clone()),
            "duplicate producer case name"
        );
        let expected_wire = decode(&case.wire_hex).expect("wire hex");
        assert_eq!(hex::encode(&expected_wire), case.wire_hex);

        let bundle = produce_elf_api_import_bundle(&artifact, case.import_index)
            .unwrap_or_else(|error| panic!("{} failed production: {error}", case.name));
        assert_eq!(
            bundle.disclosure_policy(),
            DisclosurePolicy::ReviewRequiredV1
        );
        assert_eq!(bundle.scope().platform(), ScopePlatform::Linux);
        assert_eq!(bundle.scope().format(), ScopeFormat::Elf);
        assert_eq!(bundle.observables().len(), 1);
        assert_eq!(bundle.observables()[0].kind(), ObservableKind::ApiImport);
        assert_eq!(bundle.observables()[0].value(), case.api_import);
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
        assert_eq!(reparsed.scope().platform(), ScopePlatform::Linux);
        assert_eq!(reparsed.scope().format(), ScopeFormat::Elf);
        assert_eq!(reparsed.observables()[0].value(), case.api_import);
    }
}
