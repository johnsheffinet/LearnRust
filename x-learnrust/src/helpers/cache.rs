/*
use std::time::Duration;
use axum::{Router, routing::get};
use axum_response_cache::CacheLayer;
use cached::stores::TimedSizedCache;
use tower::ServiceBuilder;

#[tokio::main]
async fn main() {
    // Initialize an in-memory cache store with a maximum of 50 entries
    // and a time-to-live (TTL) of 60 seconds for each entry.
    let cache_store = TimedSizedCache::with_size_and_lifespan(50, Duration::from_secs(60));

    // Create the Axum router.
    let app = Router::new()
        .route("/hello", get(handler))
        // Apply the Caching Layer to the route.
        // It's recommended to use ServiceBuilder when applying multiple layers.
        .layer(
            ServiceBuilder::new()
                .layer(CacheLayer::with(cache_store))
        );

    // Run the server.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn handler() -> &'static str {
    // This message will only be printed on the first request (or after the cache expires).
    println!("Handler executed (not from cache)"); 
    "Hello, world!"
}
 */