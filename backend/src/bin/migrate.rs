use std::{env, fs, process::ExitCode};

use lattice_estimator_web::{ParameterSetFile, SecurityReportFile, Validate};
use serde_json::Value;

const PARAMETER_SET_V1: &str = "lattice-security/parameter-set";
const SECURITY_REPORT_V1: &str = "lattice-security/security-report";

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("migration failed: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<String, String> {
    let mut arguments = env::args().skip(1);
    let input = arguments
        .next()
        .ok_or("usage: lattice-estimator-migrate INPUT")?;
    if arguments.next().is_some() {
        return Err("usage: lattice-estimator-migrate INPUT".to_owned());
    }

    let source =
        fs::read_to_string(&input).map_err(|error| format!("cannot read {input}: {error}"))?;
    let mut document: Value = serde_json::from_str(&source)
        .map_err(|error| format!("{input} is not valid JSON: {error}"))?;
    let object = document
        .as_object_mut()
        .ok_or("input must be a JSON object")?;
    let format = object
        .get("format")
        .and_then(Value::as_str)
        .ok_or("input has no string format field")?;
    if object.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("input must use file format version 1".to_owned());
    }

    let target = match format {
        PARAMETER_SET_V1 => "lattice-estimator/parameter-set",
        SECURITY_REPORT_V1 => "lattice-estimator/security-report",
        _ => return Err(format!("unsupported v1 format: {format}")),
    };
    object.insert("format".to_owned(), Value::String(target.to_owned()));
    object.insert("version".to_owned(), Value::from(2));

    match target {
        "lattice-estimator/parameter-set" => {
            let value: ParameterSetFile = serde_json::from_value(document.clone())
                .map_err(|error| format!("invalid parameter set: {error}"))?;
            value.validate().map_err(|error| error.to_string())?;
        }
        "lattice-estimator/security-report" => {
            let value: SecurityReportFile = serde_json::from_value(document.clone())
                .map_err(|error| format!("invalid security report: {error}"))?;
            value.validate().map_err(|error| error.to_string())?;
        }
        _ => unreachable!(),
    }

    serde_json::to_string_pretty(&document).map_err(|error| error.to_string())
}
