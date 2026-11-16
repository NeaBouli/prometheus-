//! D5 step (a): the offline covenant-id calculation writes exactly one
//! classified public file, refuses to overwrite, and fails closed without
//! output on malformed inputs. It never produces deployment material.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

const ARTIFACT: &[u8] =
    br#"{"contract_name":"ValidatorStakingH001","compiler_version":"deterministic-test","script":[81,117,81]}"#;
const SCRIPT: &[u8] = &[0x51, 0x75, 0x51];

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn temp_dir() -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "prometheus-calc-covenant-id-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(artifact: &Path, outpoint: &str, value: &str, out: &Path, artifact_sha: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_prometheus-silverc-deployer"))
        .arg("calculate-covenant-id")
        .arg("--artifact")
        .arg(artifact)
        .args(["--expected-artifact-sha256", artifact_sha])
        .args(["--expected-script-sha256", &sha256_hex(SCRIPT)])
        .args(["--funding-outpoint", outpoint])
        .args(["--genesis-output-value-sompi", value])
        .arg("--calculation-out")
        .arg(out)
        .output()
        .unwrap()
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn writes_one_classified_calculation_and_refuses_overwrite() {
    let dir = temp_dir();
    let artifact = dir.join("artifact.json");
    fs::write(&artifact, ARTIFACT).unwrap();
    let out = dir.join("calculation.json");
    let outpoint = format!("{}:3", "11".repeat(32));

    let first = run(
        &artifact,
        &outpoint,
        "1000000000",
        &out,
        &sha256_hex(ARTIFACT),
    );
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let written = fs::read(&out).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&written).unwrap();
    assert_eq!(
        value["kind"],
        "prometheus.silverc.genesis.covenant_id_calculation"
    );
    assert_eq!(
        value["classification"],
        serde_json::json!(["NOT_CHAIN_EVIDENCE", "NOT_DEPLOYMENT_AUTHORIZATION"])
    );
    assert_eq!(value["artifact_sha256"], sha256_hex(ARTIFACT));
    assert_eq!(value["contract_output_index"], 0);
    assert!(value.get("unsigned_transaction_id").is_none());
    assert!(value.get("sighash_hex").is_none());
    assert_eq!(entries(&dir), ["artifact.json", "calculation.json"]);

    let second = run(
        &artifact,
        &outpoint,
        "1000000001",
        &out,
        &sha256_hex(ARTIFACT),
    );
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("refusing to overwrite"));
    assert!(second.stdout.is_empty());
    assert_eq!(
        fs::read(&out).unwrap(),
        written,
        "existing output must stay unchanged"
    );
    assert_eq!(entries(&dir), ["artifact.json", "calculation.json"]);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_inputs_fail_closed_without_output() {
    let txid = "11".repeat(32);
    let cases: Vec<(String, &str, String)> = vec![
        (format!("{txid}:01"), "1", sha256_hex(ARTIFACT)),
        (format!("{txid}:4294967296"), "1", sha256_hex(ARTIFACT)),
        (format!("{}:0", "AB".repeat(32)), "1", sha256_hex(ARTIFACT)),
        (format!("{txid}:0"), "0", sha256_hex(ARTIFACT)),
        (format!("{txid}:0"), "-1", sha256_hex(ARTIFACT)),
        (
            format!("{txid}:0"),
            "18446744073709551616",
            sha256_hex(ARTIFACT),
        ),
        (format!("{txid}:0"), "1", "00".repeat(32)),
    ];
    for (outpoint, value, artifact_sha) in cases {
        let dir = temp_dir();
        let artifact = dir.join("artifact.json");
        fs::write(&artifact, ARTIFACT).unwrap();
        let out = dir.join("calculation.json");
        let output = run(&artifact, &outpoint, value, &out, &artifact_sha);
        assert!(
            !output.status.success(),
            "{outpoint} / {value} / {artifact_sha} must fail"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(entries(&dir), ["artifact.json"], "no output on rejection");
        fs::remove_dir_all(dir).unwrap();
    }
}
