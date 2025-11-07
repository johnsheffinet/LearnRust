/*
tower-http = { version = "0.5", features = ["cors"] }
*/

/*
use tower_http::cors::{CorsLayer, Any};

#[tokio::main]
async fn main() {
    // ...existing code...

    // Create CORS layer (allow all origins, methods, and headers for development)
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/login", post(signin))
        .merge(item_routes)
        .with_state(db)
        .layer(cors); // <-- Add CORS layer here

    // ...existing code...
}
*/