use std::{fs, process::Command};

#[test]
fn migrates_v1_parameter_set_to_valid_v2_on_stdout() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("parameters.json");
    fs::write(
        &input,
        r#"{
          "format":"lattice-security/parameter-set",
          "version":1,
          "id":"demo",
          "name":"Demo",
          "cases":[{
            "id":"lwe","name":"LWE",
            "problem":{
              "kind":"lwe","dimension":8,"modulus":"257",
              "samples":{"kind":"unlimited"},
              "secret":{"kind":"uniform_binary"},
              "error":{"kind":"centered_binomial","eta":2}
            }
          }]
        }"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_lattice-estimator-migrate"))
        .arg(input)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["format"], "lattice-estimator/parameter-set");
    assert_eq!(value["version"], 2);
}

#[test]
fn rejects_non_v1_input() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("parameters.json");
    fs::write(&input, r#"{"format":"unknown","version":1}"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lattice-estimator-migrate"))
        .arg(input)
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn migrates_v1_security_report_to_v2() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("report.json");
    let source = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("examples/demo-scheme.lattice-report.json"),
    )
    .unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&source).unwrap();
    value["format"] = "lattice-security/security-report".into();
    value["version"] = 1.into();
    fs::write(&input, serde_json::to_vec(&value).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_lattice-estimator-migrate"))
        .arg(input)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["format"], "lattice-estimator/security-report");
    assert_eq!(value["version"], 2);
}
