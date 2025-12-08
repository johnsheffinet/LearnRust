fn main() {
    println!("Hello, world!");
}
/*
// tls
use axum::{
    http::uri::Uri,
    response::Redirect,
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use tokio;

// Function to generate certs (as shown in Step 2)
fn generate_certs() {
    // ... (insert the generate_certs function from above) ...
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::fs;

    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names)
        .expect("Failed to generate self-signed certs");

    fs::create_dir_all("certs").expect("Failed to create certs directory");
    fs::write("certs/cert.pem", cert.pem.as_bytes()).expect("Failed to write cert.pem");
    fs::write("certs/key.pem", key_pair.serialize_pem().as_bytes()).expect("Failed to write key.pem");
    println!("Generated self-signed certificates in 'certs/' directory.");
}


#[tokio::main]
async fn main() {
    // Generate certificates if they don't exist
    if !std::path::Path::new("certs/cert.pem").exists() {
        generate_certs();
    }

    let http_port = 3000;
    let https_port = 3443;

    let http_server_handle = tokio::spawn(http_server(http_port, https_port));
    let https_server_handle = tokio::spawn(https_server(https_port));

    // Wait for both servers to complete (which should be never in a long-running app)
    let _ = tokio::join!(http_server_handle, https_server_handle);
}

// The HTTP server's job is purely to redirect to HTTPS
async fn http_server(http_port: u16, https_port: u16) {
    let app = Router::new().route("/*path", get(http_handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], http_port));
    println!("HTTP server listening on {}", addr);
    
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// The handler extracts the path and redirects to the HTTPS URL
async fn http_handler(uri: Uri) -> Redirect {
    let uri_string = format!("https://127.0.0.1:3443{}", uri.path());
    Redirect::temporary(&uri_string) // Use temporary redirect for development
}

// The main HTTPS server with the REST application routes
async fn https_server(https_port: u16) {
    // Configure the server to use the generated self-signed certificates
    let config = RustlsConfig::from_pem_file(
        "certs/cert.pem",
        "certs/key.pem",
    )
    .await
    .expect("Failed to load TLS config");

    // Define your application routes
    let app = Router::new()
        .route("/", get(|| async { "Hello from HTTPS!" }))
        .route("/api/data", get(|| async { "{ \"data\": \"secure data\" }" }));

    let addr = SocketAddr::from(([127, 0, 0, 1], https_port));
    println!("HTTPS server listening on {}", addr);

    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
*/
