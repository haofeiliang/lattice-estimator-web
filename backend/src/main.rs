//! `lattice-estimator-web` process entry point.
//!
//! Loads configuration, constructs shared state, binds TCP, and starts Axum.

use lattice_estimator_web::{api, service::AppConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        let url = std::env::var("LATTICE_ESTIMATOR_WEB_HEALTH_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/healthz".to_owned());
        let client = reqwest::Client::new();
        let mut request = client.get(url);
        if let Ok(token) = std::env::var("LATTICE_ESTIMATOR_WEB_API_TOKEN")
            && !token.is_empty()
        {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(format!("health endpoint returned {}", response.status()).into());
        }
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let config = AppConfig::from_environment()?;
    let state = lattice_estimator_web::service::AppState::start(&config).await?;
    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!(bind = %config.bind, "lattice estimator Web service listening");
    api::serve(listener, state).await?;
    Ok(())
}
