/*
use axum::{
    body::Bytes,
    extract::Request,
    http::{self, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use hyper::body::HttpBody as _; // for `data` and `map_err`
use tracing::{info, Level};
use tracing_subscriber::{fmt, prelude::*};

#[tokio::main]
async fn main() {
    // Initialize tracing for logging
    tracing_subscriber::registry()
        .with(fmt::layer().with_filter(fmt::filter::LevelFilter::INFO))
        .init();

    let app = Router::new()
        .route("/", get(handler))
        // Apply the logging middleware to the entire router
        .layer(axum::middleware::from_fn(log_request_response));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("Listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn handler(body: String) -> impl IntoResponse {
    // Handler consumes the body as a String
    info!("Handler received body: {}", body);
    (StatusCode::OK, format!("Hello, world! Received body length: {}", body.len()))
}

/// A middleware that logs the request and response details, including bodies.
async fn log_request_response(
    req: Request<axum::body::Body>,
    next: Next<axum::body::Body>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Log Request Info (method, uri, version, headers)
    info!(
        "Request: method={}, uri={}, version={:?}, headers={:?}",
        req.method(),
        req.uri(),
        req.version(),
        req.headers()
    );

    let (req_parts, req_body) = req.into_parts();
    // Buffer and log the request body
    let req_bytes = buffer_and_log("Request Body", req_body).await?;
    let req = Request::from_parts(req_parts, axum::body::Body::from(req_bytes));

    // Process the request
    let res = next.run(req).await;

    // Log Response Info (version, status, headers)
    info!(
        "Response: version={:?}, status={}, headers={:?}",
        res.version(),
        res.status(),
        res.headers()
    );

    let (res_parts, res_body) = res.into_parts();
    // Buffer and log the response body
    let res_bytes = buffer_and_log("Response Body", res_body).await?;
    let res = Response::from_parts(res_parts, axum::body::Body::from(res_bytes));

    Ok(res)
}

/// Helper function to buffer an async body stream into Bytes and log it.
async fn buffer_and_log(
    log_prefix: &str,
    body: axum::body::Body,
) -> Result<Bytes, (StatusCode, String)> {
    let bytes = match hyper::body::to_bytes(body).await {
        Ok(bytes) => bytes,
        Err(err) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to buffer body: {}", err),
            ));
        }
    };

    if let Ok(body_str) = std::str::from_utf8(&bytes) {
        info!("{}: {}", log_prefix, body_str);
    } else {
        info!("{}: (binary data, {} bytes)", log_prefix, bytes.len());
    }

    Ok(bytes)
}
 */
