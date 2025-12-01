/*
use axum::{
    Router,
    routing::post,
    extract::DefaultBodyLimit,
    Json,
};
use serde::Deserialize;
use std::net::SocketAddr;

// A struct to deserialize the request body into.
// The default limit applies to Json extractor.
#[derive(Deserialize, Debug)]
struct Input {
    data: String,
}

// Handler function that processes the incoming JSON data.
async fn handler(Json(input): Json<Input>) -> String {
    format!("Received data: {:?}", input)
}

#[tokio::main]
async fn main() {
    // Set up the router
    let app = Router::new()
        // Define a POST route that uses the handler
        .route("/", post(handler))
        // Apply the DefaultBodyLimit layer to the entire router.
        // This limits the body size to 1024 bytes (1 KB).
        .layer(DefaultBodyLimit::max(1024));

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
 */