/*
use axum::{
    extract::{Form, Extension},
    response::IntoResponse,
    routing::get,
    Router,
};
use axum_sessions::{SessionLayer, async_session::MemoryStore};
use axum_csrf::{CsrfConfig, CsrfToken};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use askama::Template;

#[derive(Template, Deserialize, Serialize)]
#[template(path = "form.html")]
struct FormTemplate {
    authenticity_token: String,
}

#[derive(Deserialize)]
struct FormData {
    authenticity_token: String,
    // Other form fields
    username: String,
}

// Handler to display the form
async fn show_form_handler(csrf_token: CsrfToken) -> FormTemplate {
    // The `CsrfToken` extractor makes the token available in the request extentions, 
    // and also ensures a new one is generated and set in the session/cookie if needed.
    FormTemplate {
        authenticity_token: csrf_token.authenticity_token().unwrap_or_default().to_string(),
    }
}

// Handler to process the form submission
// The `CsrfToken` extractor automatically verifies the provided token in the form data
async fn post_handler(token: CsrfToken, Form(payload): Form<FormData>) -> &'static str {
    // `token.verify(&payload.authenticity_token)` is automatically handled by the CsrfToken extractor 
    // when used with `Form` data if the library configuration is set up for it. 
    // Otherwise, you would manually verify:
    // if token.verify(&payload.authenticity_token).is_err() {
    //     return "Token is invalid";
    // }

    // If the token is valid, proceed with processing the form data
    "Token is valid, data processed successfully!"
}

#[tokio::main]
async fn main() {
    // Session setup (required by axum-csrf)
    let store = MemoryStore::new();
    let session_secret = b"some_very_long_and_secret_random_key_that_is_at_least_64_bytes_long"[..]
        .try_into()
        .expect("session secret must be 64 bytes");
    let session_layer = SessionLayer::new(store, session_secret);

    // CSRF config
    let csrf_config = CsrfConfig::default();

    // Build our application with routes and the CSRF layer
    let app = Router::new()
        .route("/", get(show_form_handler).post(post_handler))
        // Apply session and CSRF layers
        .layer(axum::middleware::from_fn(axum_csrf::csrf_middleware)) // This middleware handles verification for POST requests
        .layer(session_layer)
        .layer(Extension(csrf_config));

    // Run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
 */