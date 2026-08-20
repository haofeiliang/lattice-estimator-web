#[tokio::main]
async fn main() {
    if let Err(error) = lattice_estimator_web::cli::run(std::env::args()).await {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
