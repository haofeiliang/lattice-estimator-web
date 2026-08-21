use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use lattice_estimator_web::{
    EstimateRequest, api,
    service::{AppConfig, AppState},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

#[derive(Clone)]
struct MockState {
    calls: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
    plans: Arc<Mutex<Vec<Vec<String>>>>,
    plan_delays: Arc<Mutex<HashMap<String, Duration>>>,
    dimension_delays: Arc<Mutex<HashMap<u64, Duration>>>,
    retryable_failures: Arc<Mutex<HashMap<String, usize>>>,
    delay: Duration,
    security_bits: &'static str,
}

struct Harness {
    app: Router,
    calls: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
    plans: Arc<Mutex<Vec<Vec<String>>>>,
    plan_delays: Arc<Mutex<HashMap<String, Duration>>>,
    dimension_delays: Arc<Mutex<HashMap<u64, Duration>>>,
    retryable_failures: Arc<Mutex<HashMap<String, usize>>>,
    _directory: TempDir,
    worker: tokio::task::JoinHandle<()>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn reviewed_bounded_preflight_can_skip_both_slow_attacks() {
    let harness = harness("196", Duration::from_millis(10), None).await;
    let mut request = estimate_request("128");
    let lattice_estimator_web::Problem::Lwe(problem) = &mut request.cases[0].problem else {
        panic!("test request must contain LWE parameters");
    };
    problem.error = lattice_estimator_web::ErrorDistribution::CenteredBinomial { eta: 8 };
    let first = json_request(&harness.app, "POST", "/v1/estimates", &request, None).await;
    assert_eq!(first.0, StatusCode::ACCEPTED);
    let batch_id = first.1["batch_id"].as_str().unwrap();
    let completed = wait_for_terminal(&harness.app, batch_id).await;
    assert_eq!(completed["state"]["kind"], "completed");
    assert_eq!(harness.calls.load(Ordering::SeqCst), 2);
    let attacks = completed["report"]["reports"][0]["attacks"]
        .as_array()
        .unwrap();
    assert_eq!(
        attacks
            .iter()
            .filter(|item| item["outcome"]["code"] == "attack_preflight_above_threshold")
            .count(),
        2
    );
    assert!(
        !harness
            .plans
            .lock()
            .unwrap()
            .contains(&vec!["bkw".to_owned()])
    );

    let second = json_request(&harness.app, "POST", "/v1/estimates", &request, None).await;
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(harness.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn explicitly_forced_slow_attacks_bypass_policy_and_keep_using_cache() {
    let harness = harness("196", Duration::from_millis(10), None).await;
    let mut request = estimate_request("128");
    request.name = Some("Forced slow-attack check".to_owned());
    request.parameter_set_id = Some("slow-attack-check".to_owned());
    request.slow_attack_policy.as_mut().unwrap().forced_attacks = vec![
        lattice_estimator_web::Attack::AroraGb,
        lattice_estimator_web::Attack::Bkw,
    ];

    let first = json_request(&harness.app, "POST", "/v1/estimates", &request, None).await;
    assert_eq!(first.0, StatusCode::ACCEPTED);
    let batch_id = first.1["batch_id"].as_str().unwrap();
    let completed = wait_for_terminal(&harness.app, batch_id).await;
    assert_eq!(completed["state"]["kind"], "completed");
    let plans = harness.plans.lock().unwrap().clone();
    assert!(plans.contains(&vec!["arora_gb".to_owned()]));
    assert!(plans.contains(&vec!["bkw".to_owned()]));
    assert_eq!(harness.calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        completed["report"]["name"],
        "Forced slow-attack check security report"
    );
    assert_eq!(completed["report"]["parameter_set_id"], "slow-attack-check");

    let second = json_request(&harness.app, "POST", "/v1/estimates", &request, None).await;
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(harness.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn low_fast_result_runs_independent_slow_attack_plans() {
    let harness = harness("96", Duration::from_millis(20), None).await;
    let submitted = json_request(
        &harness.app,
        "POST",
        "/v1/estimates",
        &estimate_request("128"),
        None,
    )
    .await;
    let completed =
        wait_for_terminal(&harness.app, submitted.1["batch_id"].as_str().unwrap()).await;
    assert_eq!(completed["state"]["kind"], "completed");
    let mut plans = harness.plans.lock().unwrap().clone();
    plans.sort();
    assert!(plans.contains(&vec!["arora_gb".to_owned()]));
    assert!(plans.contains(&vec!["bkw".to_owned()]));
    assert!(plans.contains(&vec!["dual".to_owned(), "dual_hybrid".to_owned()]));
    assert!(plans.contains(&vec![
        "usvp".to_owned(),
        "bdd".to_owned(),
        "bdd_hybrid".to_owned(),
        "bdd_mitm_hybrid".to_owned()
    ]));
    assert_eq!(harness.calls.load(Ordering::SeqCst), 4);
    assert!((2..=3).contains(&harness.max_active.load(Ordering::SeqCst)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn completed_sage_plan_is_visible_before_other_plans_finish() {
    let harness = harness("196", Duration::ZERO, None).await;
    harness
        .plan_delays
        .lock()
        .unwrap()
        .insert("dual".to_owned(), Duration::from_millis(300));
    let submitted = json_request(
        &harness.app,
        "POST",
        "/v1/estimates",
        &estimate_request("128"),
        None,
    )
    .await;
    let id = submitted.1["batch_id"].as_str().unwrap();
    let partial = wait_for_detail(&harness.app, id, |detail| {
        detail["state"]["kind"] == "running"
            && detail["cases"][0]["result"]["attacks"]
                .as_array()
                .is_some_and(|attacks| !attacks.is_empty())
    })
    .await;
    let attacks = partial["cases"][0]["result"]["attacks"].as_array().unwrap();
    assert!(attacks.iter().any(|item| item["attack"] == "usvp"));
    assert!(!attacks.iter().any(|item| item["attack"] == "dual"));
    assert_eq!(
        raw_request(
            &harness.app,
            "GET",
            &format!("/v1/batches/{id}/export"),
            Body::empty(),
            None,
            None,
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let summaries = json_request(&harness.app, "GET", "/v1/batches", &json!(null), None)
        .await
        .1;
    assert_eq!(summaries[0]["batch_id"], id);
    assert!(summaries[0].get("case_count").is_some());
    assert!(summaries[0].get("request").is_none());
    assert!(summaries[0].get("cases").is_none());
    assert!(summaries[0].get("report").is_none());

    let response = raw_request(
        &harness.app,
        "GET",
        &format!("/v1/batches/{id}"),
        Body::empty(),
        None,
        None,
    )
    .await;
    let etag = response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        raw_request(
            &harness.app,
            "GET",
            &format!("/v1/batches/{id}"),
            Body::empty(),
            None,
            Some(&etag),
        )
        .await
        .status(),
        StatusCode::NOT_MODIFIED
    );
    let completed = wait_for_terminal(&harness.app, id).await;
    assert_eq!(
        completed["cases"][0]["result"]["attacks"]
            .as_array()
            .unwrap()
            .len(),
        completed["cases"][0]["expected_attack_count"]
            .as_u64()
            .unwrap() as usize
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn completed_case_is_visible_while_another_case_is_running() {
    let harness = harness("196", Duration::ZERO, None).await;
    harness
        .dimension_delays
        .lock()
        .unwrap()
        .insert(129, Duration::from_millis(300));
    let mut request = estimate_request("128");
    let mut second = request.cases[0].clone();
    second.id = "second-case".to_owned();
    second.name = "Second case".to_owned();
    let lattice_estimator_web::Problem::Lwe(problem) = &mut second.problem else {
        panic!("demo request must contain LWE parameters");
    };
    problem.dimension = 129;
    request.cases.push(second);
    let submitted = json_request(&harness.app, "POST", "/v1/estimates", &request, None).await;
    let id = submitted.1["batch_id"].as_str().unwrap();
    let progress = wait_for_detail(&harness.app, id, |detail| {
        detail["state"]["kind"] == "running"
            && detail["cases"][0]["state"]["kind"] == "completed"
            && detail["cases"][1]["state"]["kind"] == "running"
    })
    .await;
    assert!(progress["cases"][0]["result"]["attacks"].is_array());
    assert!(progress["report"].is_null());
    wait_for_terminal(&harness.app, id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn retry_clears_partial_results_and_republishes_cached_attacks() {
    let harness = harness("196", Duration::ZERO, None).await;
    harness
        .plan_delays
        .lock()
        .unwrap()
        .insert("dual".to_owned(), Duration::from_millis(100));
    harness
        .retryable_failures
        .lock()
        .unwrap()
        .insert("dual".to_owned(), 1);

    let submitted = json_request(
        &harness.app,
        "POST",
        "/v1/estimates",
        &estimate_request("128"),
        None,
    )
    .await;
    let id = submitted.1["batch_id"].as_str().unwrap();
    let retried = wait_for_detail(&harness.app, id, |detail| {
        let plans = harness.plans.lock().unwrap();
        let dual_attempts = plans
            .iter()
            .filter(|plan| plan.first().is_some_and(|attack| attack == "dual"))
            .count();
        dual_attempts >= 2
            && detail["state"]["kind"] == "running"
            && detail["cases"][0]["result"]["attacks"]
                .as_array()
                .is_some_and(|attacks| attacks.iter().any(|item| item["attack"] == "usvp"))
    })
    .await;
    assert_eq!(retried["cases"][0]["state"]["kind"], "running");

    let completed = wait_for_terminal(&harness.app, id).await;
    assert_eq!(completed["state"]["kind"], "completed");
    let plans = harness.plans.lock().unwrap();
    assert_eq!(
        plans
            .iter()
            .filter(|plan| plan.first().is_some_and(|attack| attack == "dual"))
            .count(),
        2
    );
    assert_eq!(
        plans
            .iter()
            .filter(|plan| plan.first().is_some_and(|attack| attack == "usvp"))
            .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn etag_and_batch_deletion_keep_the_attack_cache() {
    let harness = harness("196", Duration::ZERO, None).await;
    let request = estimate_request("128");
    let submitted = json_request(&harness.app, "POST", "/v1/estimates", &request, None).await;
    let id = submitted.1["batch_id"].as_str().unwrap().to_owned();
    let completed = wait_for_terminal(&harness.app, &id).await;
    let revision = completed["revision"].as_u64().unwrap();
    let response = raw_request(
        &harness.app,
        "GET",
        &format!("/v1/batches/{id}"),
        Body::empty(),
        None,
        Some(&format!("\"{revision}\"")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        raw_request(
            &harness.app,
            "DELETE",
            &format!("/v1/batches/{id}"),
            Body::empty(),
            None,
            None
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let cached = json_request(&harness.app, "POST", "/v1/estimates", &request, None).await;
    assert_eq!(cached.0, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parameter_set_replace_and_delete_are_exposed_as_use_cases() {
    let harness = harness("196", Duration::ZERO, None).await;
    let mut set: Value = serde_json::from_str(include_str!(
        "../../examples/demo-scheme.lattice-params.json"
    ))
    .unwrap();
    let first = json_request(
        &harness.app,
        "POST",
        "/v1/parameter-sets/import",
        &set,
        None,
    )
    .await;
    assert_eq!(first.0, StatusCode::CREATED);
    set["name"] = json!("updated");
    let second = json_request(
        &harness.app,
        "POST",
        "/v1/parameter-sets/import?conflict=replace",
        &set,
        None,
    )
    .await;
    assert_eq!(second.1["version"], 2);
    let listed = json_request(
        &harness.app,
        "GET",
        "/v1/parameter-sets",
        &json!(null),
        None,
    )
    .await;
    assert_eq!(listed.1[0]["name"], "updated");
    let id = set["id"].as_str().unwrap();
    assert_eq!(
        raw_request(
            &harness.app,
            "DELETE",
            &format!("/v1/parameter-sets/{id}"),
            Body::empty(),
            None,
            None
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn bulk_delete_removes_multiple_parameter_sets_and_finished_batches() {
    let harness = harness("196", Duration::ZERO, None).await;
    let mut set: Value = serde_json::from_str(include_str!(
        "../../examples/demo-scheme.lattice-params.json"
    ))
    .unwrap();
    for id in ["bulk-set-a", "bulk-set-b"] {
        set["id"] = json!(id);
        assert_eq!(
            json_request(
                &harness.app,
                "POST",
                "/v1/parameter-sets/import",
                &set,
                None,
            )
            .await
            .0,
            StatusCode::CREATED
        );
    }
    assert_eq!(
        json_request(
            &harness.app,
            "POST",
            "/v1/parameter-sets/bulk-delete",
            &json!({ "ids": ["bulk-set-a", "bulk-set-b"] }),
            None,
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        json_request(
            &harness.app,
            "GET",
            "/v1/parameter-sets",
            &Value::Null,
            None,
        )
        .await
        .1,
        json!([])
    );

    let request = estimate_request("128");
    let first = json_request(&harness.app, "POST", "/v1/estimates", &request, None).await;
    let first_id = first.1["batch_id"].as_str().unwrap().to_owned();
    wait_for_terminal(&harness.app, &first_id).await;
    let second = json_request(&harness.app, "POST", "/v1/estimates", &request, None).await;
    let second_id = second.1["batch_id"].as_str().unwrap().to_owned();
    assert_eq!(
        json_request(
            &harness.app,
            "POST",
            "/v1/batches/bulk-delete",
            &json!({ "ids": [first_id, second_id] }),
            None,
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        json_request(&harness.app, "GET", "/v1/batches", &Value::Null, None)
            .await
            .1,
        json!([])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_protects_api_and_errors_use_the_public_envelope() {
    let harness = harness("196", Duration::ZERO, Some("secret".to_owned())).await;
    let denied = raw_request(
        &harness.app,
        "GET",
        "/v1/metadata",
        Body::empty(),
        None,
        None,
    )
    .await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let allowed = raw_request(
        &harness.app,
        "GET",
        "/v1/metadata",
        Body::empty(),
        Some("secret"),
        None,
    )
    .await;
    assert_eq!(allowed.status(), StatusCode::OK);
    let invalid = raw_request(
        &harness.app,
        "POST",
        "/v1/estimates",
        Body::from("{"),
        Some("secret"),
        None,
    )
    .await;
    let value: Value =
        serde_json::from_slice(&to_bytes(invalid.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(value["code"], "bad_request");
    assert!(value["request_id"].as_str().is_some());
}

async fn harness(
    security_bits: &'static str,
    delay: Duration,
    api_token: Option<String>,
) -> Harness {
    let calls = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));
    let plans = Arc::new(Mutex::new(Vec::new()));
    let plan_delays = Arc::new(Mutex::new(HashMap::new()));
    let dimension_delays = Arc::new(Mutex::new(HashMap::new()));
    let retryable_failures = Arc::new(Mutex::new(HashMap::new()));
    let worker_state = MockState {
        calls: calls.clone(),
        active,
        max_active: max_active.clone(),
        plans: plans.clone(),
        plan_delays: plan_delays.clone(),
        dimension_delays: dimension_delays.clone(),
        retryable_failures: retryable_failures.clone(),
        delay,
        security_bits,
    };
    let worker_router = Router::new()
        .route("/v1/metadata", get(mock_metadata))
        .route("/v1/estimate", post(mock_estimate))
        .route("/v1/preflight", post(mock_preflight))
        .with_state(worker_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let worker = tokio::spawn(async move {
        axum::serve(listener, worker_router).await.unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let config = AppConfig {
        bind: "127.0.0.1:0".to_owned(),
        database_path: directory.path().join("test.db"),
        estimator_url: format!("http://{address}/"),
        poll_after_seconds: 0,
        api_token,
        web_dir: directory.path().join("web"),
        case_concurrency: 2,
        estimator_concurrency: 3,
    };
    let state = AppState::start(&config).await.unwrap();
    Harness {
        app: api::router(state),
        calls,
        max_active,
        plans,
        plan_delays,
        dimension_delays,
        retryable_failures,
        _directory: directory,
        worker,
    }
}

async fn mock_metadata() -> Json<Value> {
    Json(json!({
        "adapter_schema_version": 2,
        "estimator_commit": "6019056011d10d7e9c30a0d5da2d2f729fbc2eec", "sage_version": "10.9",
        "adapter_version": "2", "worker_image": "mock-worker", "platform": "linux/amd64",
        "support_matrix": {}, "adaptive_attacks": ["arora_gb", "bkw"]
    }))
}

async fn mock_estimate(State(state): State<MockState>, Json(request): Json<Value>) -> Json<Value> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
    state.max_active.fetch_max(active, Ordering::SeqCst);
    let targets = request["target_attacks"].as_array().unwrap().clone();
    state.plans.lock().unwrap().push(
        targets
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect(),
    );
    let dimension = request["problem"]["dimension"].as_u64();
    let plan = targets.first().and_then(Value::as_str);
    let delay = dimension
        .and_then(|dimension| {
            state
                .dimension_delays
                .lock()
                .unwrap()
                .get(&dimension)
                .copied()
        })
        .or_else(|| plan.and_then(|attack| state.plan_delays.lock().unwrap().get(attack).copied()))
        .unwrap_or(state.delay);
    tokio::time::sleep(delay).await;
    let retryable_failure = plan.is_some_and(|attack| {
        let mut failures = state.retryable_failures.lock().unwrap();
        let remaining = failures.entry(attack.to_owned()).or_default();
        if *remaining == 0 {
            false
        } else {
            *remaining -= 1;
            true
        }
    });
    let results = targets
        .into_iter()
        .map(|attack| {
            if retryable_failure {
                json!({
                    "attack": attack,
                    "outcome": {
                        "kind": "failed",
                        "code": "mock_retryable_failure",
                        "message": "transient mock failure",
                        "retryable": true
                    }
                })
            } else {
                json!({
                    "attack": attack,
                    "outcome": {
                        "kind": "computed",
                        "security_bits": state.security_bits,
                        "metrics": {}
                    }
                })
            }
        })
        .collect::<Vec<_>>();
    state.active.fetch_sub(1, Ordering::SeqCst);
    Json(json!({
        "schema_version": 2,
        "results": results, "duration_ms": 1,
        "provenance": { "estimator_commit": "6019056011d10d7e9c30a0d5da2d2f729fbc2eec", "sage_version": "10.9", "adapter_version": "2", "adapter_schema_version": 2, "worker_image": "mock-worker" }
    }))
}

async fn mock_preflight(State(state): State<MockState>, Json(request): Json<Value>) -> Json<Value> {
    let results = request["target_attacks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|attack| {
            json!({
                "attack": attack,
                "outcome": {
                    "kind": "computed",
                    "security_bits": state.security_bits,
                    "metrics": {
                        "preflight_rule_version": {"kind": "integer", "value": "4"}
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    Json(json!({
        "schema_version": 2,
        "results": results,
        "duration_ms": 1,
        "provenance": {
            "estimator_commit": "6019056011d10d7e9c30a0d5da2d2f729fbc2eec",
            "sage_version": "10.9",
            "adapter_version": "2",
            "adapter_schema_version": 2,
            "worker_image": "mock-worker"
        }
    }))
}

fn estimate_request(required_security: &str) -> EstimateRequest {
    let mut value: Value =
        serde_json::from_str(include_str!("../../examples/demo-run.json")).unwrap();
    value["timeout_seconds"] = json!(10);
    value["slow_attack_policy"]["required_security_bits"] = json!(required_security);
    value["slow_attack_policy"]["stop_margin_bits"] = json!("16");
    let mut request: EstimateRequest = serde_json::from_value(value).unwrap();
    let lattice_estimator_web::Problem::Lwe(problem) = &mut request.cases[0].problem else {
        panic!("demo request must contain LWE parameters");
    };
    problem.dimension = 128;
    problem.modulus = lattice_estimator_web::PositiveInteger::new("256").unwrap();
    request
}

async fn json_request<T: serde::Serialize>(
    app: &Router,
    method: &str,
    uri: &str,
    value: &T,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let body = if method == "GET" {
        Body::empty()
    } else {
        Body::from(serde_json::to_vec(value).unwrap())
    };
    let response = raw_request(app, method, uri, body, token, None).await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

async fn raw_request(
    app: &Router,
    method: &str,
    uri: &str,
    body: Body,
    token: Option<&str>,
    etag: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(etag) = etag {
        builder = builder.header(header::IF_NONE_MATCH, etag);
    }
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}

async fn wait_for_terminal(app: &Router, id: &str) -> Value {
    for _ in 0..200 {
        let response = json_request(app, "GET", &format!("/v1/batches/{id}"), &json!(null), None)
            .await
            .1;
        if matches!(
            response["state"]["kind"].as_str(),
            Some("completed" | "partial" | "timed_out" | "cancelled" | "failed")
        ) {
            return response;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("batch did not finish")
}

async fn wait_for_detail(app: &Router, id: &str, predicate: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..200 {
        let detail = json_request(app, "GET", &format!("/v1/batches/{id}"), &Value::Null, None)
            .await
            .1;
        if predicate(&detail) {
            return detail;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("batch detail did not reach the expected progress state")
}
