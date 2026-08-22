//! Thin executable wrapper for the reusable HTTP CLI implementation.

#[tokio::main]
async fn main() {
    if let Err(error) = lattice_estimator_web::cli::run(std::env::args()).await {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
