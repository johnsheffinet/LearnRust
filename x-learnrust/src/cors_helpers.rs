/*
use axum::{routing::get, http::StatusCode, Router};
use std::net::SocketAddr;

// A simple handler that returns a message and an OK status
async fn same_origin_handler() -> (StatusCode, &'static str) {
    (StatusCode::OK, "Hello! This content is only available to same-origin requests.")
}

#[tokio::main]
async fn main() {
    // Build the application router.
    // By default, no CORS headers are added, so cross-origin requests
    // will be blocked by web browsers adhering to the same-origin policy.
    let app = Router::new()
        .route("/", get(same_origin_handler));

    // Run the application
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on http://{}", addr);
    axum::serve(
        tokio::net::TcpListener::bind(&addr).await.unwrap(),
        app,
    )
    .await
    .unwrap();
}
 */
