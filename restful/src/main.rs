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

/*
// trc
use axum::{
    body::{Body, Bytes},
    http::{Request, Response, StatusCode, HeaderMap, Method, Version},
    middleware::{self, Next},
    routing::get,
    Router,
};
use std::net::SocketAddr;
use futures_util::future::BoxFuture;
use tower::{Service, Layer};
use std::task::{Context, Poll};
use tracing::{info, Level};
use tracing_subscriber::{fmt, prelude::*, filter::LevelFilter};

// A helper function to buffer and print the body.
// This is necessary because the body is a stream and must be consumed or re-wrapped.
async fn buffer_and_print(label: &str, body: Body) -> Result<Bytes, StatusCode> {
    let bytes = hyper::body::to_bytes(body)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !bytes.is_empty() {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            info!("{} body: {}", label, s);
        } else {
            info!("{} body (binary): {:?}", label, bytes);
        }
    } else {
        info!("{} body: (empty)", label);
    }

    Ok(bytes)
}

// The core middleware function
async fn logging_middleware(
    req: Request<Body>,
    next: Next<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let (req_parts, req_body) = req.into_parts();
    
    // Log Request details
    info!("Incoming Request:");
    info!("- Method: {:?}", req_parts.method);
    info!("- URI: {:?}", req_parts.uri);
    info!("- Version: {:?}", req_parts.version);
    info!("- Headers: {:#?}", req_parts.headers);

    // Buffer and log the request body, then create a new request with the buffered body
    let req_bytes = buffer_and_print("Request", req_body).await.map_err(|e| (e, "Bad request body".to_string()))?;
    let req = Request::from_parts(req_parts, Body::from(req_bytes));

    // Process the request
    let res = next.run(req).await;

    let (res_parts, res_body) = res.into_parts();

    // Log Response details
    info!("Outgoing Response:");
    info!("- Version: {:?}", res_parts.version);
    info!("- Status: {:?}", res_parts.status);
    info!("- Headers: {:#?}", res_parts.headers);

    // Buffer and log the response body, then create a new response with the buffered body
    let res_bytes = buffer_and_print("Response", res_body).await.map_err(|e| (e, "Bad response body".to_string()))?;
    let res = Response::from_parts(res_parts, Body::from(res_bytes));
    
    Ok(res)
}

// A simple handler
async fn hello_world() -> &'static str {
    "Hello, World!"
}

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    // Build the application with the custom middleware layer
    let app = Router::new()
        .route("/", get(hello_world))
        // Apply the middleware as a layer
        .layer(middleware::from_fn(logging_middleware));

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
 */
