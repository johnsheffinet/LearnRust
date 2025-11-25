/*
use axum::{
    http::uri::Uri,
    response::{IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use serde::Serialize;
use std::net::SocketAddr;

// Define a simple structure for a REST response
#[derive(Serialize)]
struct Message {
    message: String,
}

#[tokio::main]
async fn main() {
    // Certificate path (adjust as needed based on your generation method)
    let cert_path = "certs/cert.pem";
    let key_path = "certs/key.pem";
    
    // --- HTTPS Server Setup ---
    let https_app = Router::new().route("/api/data", get(data_handler));
    
    let https_addr = SocketAddr::from(([127, 0, 0, 1], 3443));
    println!("HTTPS listening on {}", https_addr);

    // Load TLS config
    let config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .expect("Failed to load TLS certificates");

    let https_server = axum_server::bind_rustls(https_addr, config)
        .serve(https_app.into_make_service());

    // --- HTTP Server Setup for Redirection ---
    let http_app = Router::new().route("/*path", get(http_handler));
    
    let http_addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("HTTP listening on {}", http_addr);

    let http_server = axum_server::bind(http_addr)
        .serve(http_app.into_make_service());

    // Run both servers concurrently
    tokio::join!(
        tokio::spawn(https_server),
        tokio::spawn(http_server)
    );
}

// Handler for the HTTPS REST endpoint
async fn data_handler() -> impl IntoResponse {
    let data = Message {
        message: "Hello from HTTPS REST API!".to_string(),
    };
    Json(data)
}

// Handler for the HTTP requests to redirect to HTTPS
async fn http_handler(uri: Uri) -> Redirect {
    // Construct the new HTTPS URI
    let https_uri = format!("https://127.0.0.1:3443{}", uri.path());
    
    // Use a temporary redirect (307) to preserve the original method and body if necessary
    Redirect::temporary(&https_uri)
}
 */
