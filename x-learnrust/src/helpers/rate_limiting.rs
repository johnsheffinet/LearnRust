/*
use axum::{
    routing::get,
    Router,
};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use axum_governor::{GovernorLayer, GovernorConfigBuilder};
use real::axum::RealIpLayer;
use std::time::Duration;

// Define the rate limiting configuration
// 5 requests per second per IP address
let governor_config = GovernorConfigBuilder::default()
    .frequency(Duration::from_secs(1))
    .burst_size(5)
    .finish()
    .expect("Failed to build governor config");

// Handler function
async fn handler() -> &'static str {
    "Hello, World!"
}

#[tokio::main]
async fn main() {
    // Build the Axum app with the rate limiting layers
    let app = Router::new()
        .route("/", get(handler))
        // Apply the layers:
        // 1. RealIpLayer: Extracts the client's real IP address
        // 2. GovernorLayer: Applies the rate limiting rules based on the IP
        .layer(
            ServiceBuilder::new()
                .layer(RealIpLayer::default())
                .layer(GovernorLayer::new(&governor_config))
        );

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
 */