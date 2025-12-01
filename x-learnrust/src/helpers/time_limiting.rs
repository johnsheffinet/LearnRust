/*
use axum::{
    routing::get,
    error_handling::HandleErrorLayer,
    http::StatusCode,
    BoxError,
    Router,
};
use tower::{ServiceBuilder, timeout::TimeoutLayer};
use std::time::Duration;
use std::convert::Infallible;

// A handler that might take too long to respond
async fn slow_handler() -> String {
    // Simulate a long-running operation
    tokio::time::sleep(Duration::from_secs(5)).await;
    "This was a slow response!".to_string()
}

// A handler that responds within the timeout
async fn fast_handler() -> String {
    "This was a fast response!".to_string()
}

// The error handler for when a request times out
async fn handle_timeout_error(_: BoxError) -> (StatusCode, &'static str) {
    (StatusCode::REQUEST_TIMEOUT, "Request timed out")
}

#[tokio::main]
async fn main() {
    let timeout_duration = Duration::from_secs(2); // Set the timeout duration

    // Use a ServiceBuilder to combine layers
    let service = ServiceBuilder::new()
        // This layer handles errors returned by layers below it, including TimeoutLayer
        .layer(HandleErrorLayer::new(handle_timeout_error))
        // This layer applies a timeout to the service below it
        .layer(TimeoutLayer::new(timeout_duration));

    // Build the Axum application
    let app = Router::new()
        .route("/slow", get(slow_handler))
        .route("/fast", get(fast_handler))
        // Apply the service builder as a layer to the router
        .layer(service);

    // Run the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("Server running on http://127.0.0.1:3000");

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
 */