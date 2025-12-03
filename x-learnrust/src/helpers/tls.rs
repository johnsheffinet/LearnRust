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

use axum::{
    http::uri::Uri,
    response::Redirect,
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use tokio;

#[tokio::main]
async fn main() {
    // Spawn the HTTP server task
    let http = tokio::spawn(http_server());
    // Spawn the HTTPS server task
    let https = tokio::spawn(https_server());

    println!("HTTP server running on http://localhost:3000");
    println!("HTTPS server running on https://localhost:3443");

    // Wait for both servers to complete (which will be never in this case)
    let _ = tokio::join!(http, https);
}

// Function to run the HTTP server which redirects to HTTPS
async fn http_server() {
    let app = Router::new().route("/", get(http_handler));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// Handler to redirect the incoming HTTP request URI to the HTTPS URI
async fn http_handler(uri: Uri) -> Redirect {
    let uri = format!("https://127.0.0.1:3443{}", uri.path());
    
    // Use a 307 Temporary Redirect status code
    Redirect::temporary(&uri)
}
/// A dedicated server that catches all HTTP traffic and redirects to HTTPS.
async fn redirect_http_to_https() {
    let http_addr = SocketAddr::from(([0, 0, 0, 0], 80));

    // A service that handles *all* incoming HTTP requests
    let service = tower::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
        let uri = req.uri();

        // Use the Host header to determine the original hostname, falling back to localhost
        let host = req.headers()
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");
            
        // Reconstruct the URI with the https scheme and correct host/path
        // We use the 308 code to preserve the HTTP method during redirection.
        let https_uri_string = format!("https://{}{}", host, uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
        
        let location = https_uri_string.parse::<Uri>().expect("Invalid URI");

        // Create the redirect response
        let response = axum::response::Redirect::permanent(&location.to_string());
        
        Ok::<_, std::convert::Infallible>(response.into_response())
    });

    println!("Listening for HTTP redirects on {}", http_addr);

    // Bind to port 80 and run the redirection service
    let listener = TcpListener::bind(&http_addr).await.unwrap();
    axum::serve(listener, service.into_make_service()).await.unwrap();
}
// Function to run the HTTPS server
async fn https_server() {
    // Load the self-signed certificates and key
    let config = RustlsConfig::from_pem_file(
        "certs/cert.pem",
        "certs/key.pem",
    )
    .await
    .unwrap();

    // The main application router with secure handlers
    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        .route("/api/data", get(|| async { "{\"message\": \"Secure data delivered over HTTPS\"}" }));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3443));
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
 */

/*
mod helpers;
use crate::helpers::tls;
use crate::helpers::utils;

#[tokio::main]
async fn main() {

    let http_addr: String = utils::read_env_var("HTTP_ADDR");
    let https_addr: String = utils::read_env_var("HTTPS_ADDR");
    let key_path: String = utils::read_env_var("KEY_PATH");
    let cert_path: String = utils::read_env_var("CERT_PATH");

    let serve_http_app_task = tokio::spawn(
        tls::serve_http_app(
            &http_addr,
            &https_addr
        )
    );
    
    let _ = serve_http_app_task.await;
}

pub mod helpers {
    use std::{env, f32::consts::E};

    pub fn read_env_var(key: &str) -> String {
        env::var(key)
            .expect(&format!(
                "Failed to read {} environment variable!", 
                key,
            )
        )
    }
    pub mod tls {
        use axum::{http::Uri, response::Redirect, routing::get, Router};
        use axum_server::tls_rustls::RustlsConfig;
        use crate::helpers;
        use std::net::SocketAddr;

        pub async fn serve_https_app(
            https_addr_env_var: &str,
            cert_path_env_var: &str,
            key_path_env_var: &str,
        ) {
            let https_addr= helpers::read_env_var(https_addr_env_var).await;
            let cert_path = helpers::read_env_var(cert_path_env_var).await;
            let key_path = helpers::read_env_var(key_path_env_var).await;

            let addr: SocketAddr = https_addr
                .parse()
                .expect(&format!(
                        "Failed to parse {} into socket address!", 
                        https_addr,
                    )
                );

            let config:RustlsConfig = RustlsConfig::from_pem_file(
                    &cert_path, 
                    &key_path,
                )
                .await
                .expect(&format!(
                        "Failed to read {} or {} files!",
                        &cert_path,
                        &key_path,
                    )
                );

            let app: Router = Router::new()
                .route("/", get(|| async {"Hello from https app.\n"}));

            axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service())
                .await
                .expect(&format!(
                        "Failed to serve https app on {}",
                        addr,
                    )
                );
        }

        pub async fn serve_http_app(
            http_addr: &str,
            https_addr: &str,
        ) {
            let addr = http_addr
                .parse()
                .expect(&format!(
                    "Failed to parse {} into socket address!",
                    http_addr,
                    )
                );

            let redirect_addr = https_addr
                .parse()
                .expect(&format!(
                    "Failed to parse {} into socket address!",
                    https_addr,
                    )
                );

            let app = Router::new()
                .route("/*path", get(redirect_to_https));

            axum_server::bind(addr)
                .serve(app.into_make_service())
                .await
                .expect(&format!("Failed to serve http app on {}!", addr));
        }

        async fn redirect_to_https(uri: Uri) -> Redirect {
            // let https_uri = format!("https://{}{}", redirect_addr, uri.path());
            // Redirect::temporary(&https_uri)
            // axum_server::response::Redirect::to(&format!("https://{}{}, redirect_addr, uri.path()").with_status(StatusCode::TEMPORARY_REDIRECT)
        }
    }
}
 */

/*
[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
hyper = { version = "1.0", features = ["full"] }
tower = "0.4"
http = "1.0"
# For real HTTPS, you'd add 'axum-server' or similar crates
 */

/*
#[tokio::main]
async fn main() {
    let redirect_to_https_task = tokio::spawn(redirect_to_https(
            &http_addr,
            &https_addr,
        )
    );

    let server_app_over_https_task = tokio::spawn(serve_app_over_https(
            &https_addr,
            &key_path,
            &cert_path,
        )
    );

    tokio::join!(
        redirect_req_to_https_task,
        serve_app_over_https_task,
    );
}
    // --- Main HTTPS Server Setup (Port 443) ---
    // NOTE: A real application requires a crate like `axum-server` or a reverse proxy for actual TLS.
    let app = Router::new()
        .route("/", get(|| async { "Hello from HTTPS!" }))
        .route("/*path", get(|| async { "Secure content accessed." }));
        
    let https_addr = SocketAddr::from(([0, 0, 0, 0], 443));
    println!("Listening for HTTPS on {}", https_addr);

    // This is a placeholder for actual HTTPS server binding:
    let listener = TcpListener::bind(&https_addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await.unwrap();
}

/// A dedicated server that catches all HTTP traffic and redirects to HTTPS.
async fn redirect_http_to_https() {
    let http_addr = SocketAddr::from(([0, 0, 0, 0], 80));

    // A service that handles *all* incoming HTTP requests
    let service = tower::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
        let uri = req.uri();

        // Use the Host header to determine the original hostname, falling back to localhost
        let host = req.headers()
            .get("Host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");
            
        // Reconstruct the URI with the https scheme and correct host/path
        // We use the 308 code to preserve the HTTP method during redirection.
        let https_uri_string = format!("https://{}{}", host, uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
        
        let location = https_uri_string.parse::<Uri>().expect("Invalid URI");

        // Create the redirect response
        let response = axum::response::Redirect::permanent(&location.to_string());
        
        Ok::<_, std::convert::Infallible>(response.into_response())
    });

    println!("Listening for HTTP redirects on {}", http_addr);

    // Bind to port 80 and run the redirection service
    let listener = TcpListener::bind(&http_addr).await.unwrap();
    axum::serve(listener, service.into_make_service()).await.unwrap();
}
 */
