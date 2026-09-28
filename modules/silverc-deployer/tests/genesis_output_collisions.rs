//! PRM-06: every genesis subcommand that writes output must reject an output
//! path aliasing an input or another output before any read, write, journal,
//! lock, broadcast, or observation side effect.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const FIXTURE: &[u8] = b"public fixture, not json";
const ACK: &str = "0000000000000000000000000000000000000000000000000000000000000000";

struct Subcommand {
    name: &'static str,
    inputs: &'static [(&'static str, &'static str)],
    outputs: &'static [(&'static str, &'static str)],
    extra: &'static [&'static str],
}

const GENESIS_INPUTS: &[(&str, &str)] = &[
    ("--request", "request input"),
    ("--artifact", "artifact input"),
    ("--funding", "funding input"),
    ("--signing-request", "signing-request input"),
    ("--signature-response", "signature-response input"),
];

const SUBCOMMANDS: &[Subcommand] = &[
    Subcommand {
        name: "preflight",
        inputs: &[
            ("--request", "request input"),
            ("--funding", "funding input"),
        ],
        outputs: &[("--evidence-out", "preflight evidence output")],
        extra: &[],
    },
    Subcommand {
        name: "prepare",
        inputs: &[
            ("--request", "request input"),
            ("--artifact", "artifact input"),
            ("--funding", "funding input"),
        ],
        outputs: &[("--signing-request-out", "signing-request output")],
        extra: &[],
    },
    Subcommand {
        name: "import-signature",
        inputs: &[
            ("--request", "request input"),
            ("--artifact", "artifact input"),
            ("--funding", "funding input"),
            ("--signing-request", "signing-request input"),
            ("--signature-hex-file", "signature input"),
        ],
        outputs: &[
            ("--signature-response-out", "signature-response output"),
            ("--verification-out", "verification output"),
        ],
        extra: &[],
    },
    Subcommand {
        name: "verify-signature",
        inputs: GENESIS_INPUTS,
        outputs: &[("--verification-out", "verification output")],
        extra: &[],
    },
    Subcommand {
        name: "broadcast",
        inputs: GENESIS_INPUTS,
        outputs: &[("--result-out", "broadcast result output")],
        extra: &["--acknowledge-signing-request-sha256", ACK],
    },
    Subcommand {
        name: "observe",
        inputs: GENESIS_INPUTS,
        outputs: &[("--evidence-out", "observation evidence output")],
        extra: &[],
    },
];

fn temp_dir(label: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "prometheus-genesis-collisions-{}-{}-{label}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(dir).unwrap()
}

fn write_inputs(dir: &Path, command: &Subcommand) -> BTreeMap<&'static str, PathBuf> {
    command
        .inputs
        .iter()
        .map(|(flag, _)| {
            let path = dir.join(format!("{}.input", flag.trim_start_matches('-')));
            fs::write(&path, FIXTURE).unwrap();
            (*flag, path)
        })
        .collect()
}

fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut entries = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                pending.push(path.clone());
                entries.insert(path, None);
            } else if metadata.file_type().is_symlink() {
                entries.insert(
                    path.clone(),
                    Some(
                        fs::read_link(&path)
                            .unwrap()
                            .into_os_string()
                            .into_encoded_bytes(),
                    ),
                );
            } else {
                entries.insert(path.clone(), Some(fs::read(&path).unwrap()));
            }
        }
    }
    entries
}

fn run(
    command: &Subcommand,
    inputs: &BTreeMap<&'static str, PathBuf>,
    outputs: &BTreeMap<&'static str, PathBuf>,
) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_prometheus-silverc-deployer"));
    process.arg(command.name);
    for (flag, path) in inputs.iter().chain(outputs.iter()) {
        process.arg(flag).arg(path);
    }
    process.args(command.extra);
    process.output().unwrap()
}

fn assert_rejected_without_side_effects(
    command: &Subcommand,
    inputs: &BTreeMap<&'static str, PathBuf>,
    outputs: &BTreeMap<&'static str, PathBuf>,
    dir: &Path,
    expected: &str,
) {
    let before = snapshot(dir);
    let output = run(command, inputs, outputs);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{}: must fail", command.name);
    assert!(
        stderr.contains(expected),
        "{}: expected `{expected}`, got `{stderr}`",
        command.name
    );
    assert!(
        output.stdout.is_empty(),
        "{}: no public output",
        command.name
    );
    assert_eq!(
        snapshot(dir),
        before,
        "{}: rejection must not read, create, truncate, or replace any file",
        command.name
    );
}

fn distinct_outputs(dir: &Path, command: &Subcommand) -> BTreeMap<&'static str, PathBuf> {
    command
        .outputs
        .iter()
        .map(|(flag, _)| {
            (
                *flag,
                dir.join(format!("{}.json", flag.trim_start_matches('-'))),
            )
        })
        .collect()
}

#[test]
fn rejects_every_output_equal_to_every_input() {
    for command in SUBCOMMANDS {
        for (output_flag, output_label) in command.outputs {
            for (input_flag, input_label) in command.inputs {
                let dir = temp_dir(command.name);
                let inputs = write_inputs(&dir, command);
                let mut outputs = distinct_outputs(&dir, command);
                outputs.insert(output_flag, inputs[input_flag].clone());
                assert_rejected_without_side_effects(
                    command,
                    &inputs,
                    &outputs,
                    &dir,
                    &format!("{output_label} collides with {input_label}"),
                );
                fs::remove_dir_all(dir).unwrap();
            }
        }
    }
}

#[test]
fn rejects_lexically_aliased_output_paths() {
    for command in SUBCOMMANDS {
        let dir = temp_dir(command.name);
        let inputs = write_inputs(&dir, command);
        fs::create_dir(dir.join("alias")).unwrap();
        let (input_flag, input_label) = command.inputs[0];
        let (output_flag, output_label) = command.outputs[0];
        let mut outputs = distinct_outputs(&dir, command);
        outputs.insert(
            output_flag,
            dir.join("alias")
                .join("..")
                .join(inputs[input_flag].file_name().unwrap()),
        );
        assert_rejected_without_side_effects(
            command,
            &inputs,
            &outputs,
            &dir,
            &format!("{output_label} collides with {input_label}"),
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn rejects_symlink_output_aliasing_an_input() {
    for command in SUBCOMMANDS {
        let dir = temp_dir(command.name);
        let inputs = write_inputs(&dir, command);
        let (input_flag, input_label) = command.inputs[command.inputs.len() - 1];
        let (output_flag, output_label) = command.outputs[0];
        let link = dir.join("output-link.json");
        std::os::unix::fs::symlink(&inputs[input_flag], &link).unwrap();
        let mut outputs = distinct_outputs(&dir, command);
        outputs.insert(output_flag, link);
        assert_rejected_without_side_effects(
            command,
            &inputs,
            &outputs,
            &dir,
            &format!("{output_label} collides with {input_label}"),
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn rejects_broadcast_journal_aliasing_an_input() {
    let command = SUBCOMMANDS.iter().find(|c| c.name == "broadcast").unwrap();
    for (input_flag, input_label) in command.inputs {
        let dir = temp_dir("broadcast-journal");
        let mut inputs = write_inputs(&dir, command);
        let result_out = dir.join("result.json");
        let journal = dir.join("result.json.intent.json");
        fs::rename(&inputs[input_flag], &journal).unwrap();
        inputs.insert(input_flag, journal);
        let outputs = BTreeMap::from([("--result-out", result_out)]);
        assert_rejected_without_side_effects(
            command,
            &inputs,
            &outputs,
            &dir,
            &format!("broadcast journal output collides with {input_label}"),
        );
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn rejects_pairwise_output_collisions() {
    let command = SUBCOMMANDS
        .iter()
        .find(|c| c.name == "import-signature")
        .unwrap();
    let dir = temp_dir("pairwise");
    let inputs = write_inputs(&dir, command);
    let shared = dir.join("shared-output.json");
    let outputs = BTreeMap::from([
        ("--signature-response-out", shared.clone()),
        (
            "--verification-out",
            dir.join("alias-free").join("..").join("shared-output.json"),
        ),
    ]);
    fs::create_dir(dir.join("alias-free")).unwrap();
    assert_rejected_without_side_effects(
        command,
        &inputs,
        &outputs,
        &dir,
        "verification output collides with signature-response output",
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn distinct_paths_pass_the_collision_gate() {
    for command in SUBCOMMANDS {
        let dir = temp_dir(command.name);
        let inputs = write_inputs(&dir, command);
        let outputs = distinct_outputs(&dir, command);
        let output = run(command, &inputs, &outputs);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{}: fixture is not valid json",
            command.name
        );
        assert!(
            !stderr.contains("collides with"),
            "{}: distinct paths must not collide: {stderr}",
            command.name
        );
        for path in outputs.values() {
            assert!(
                !path.exists(),
                "{}: invalid input must not write output",
                command.name
            );
        }
        for path in inputs.values() {
            assert_eq!(fs::read(path).unwrap(), FIXTURE);
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
