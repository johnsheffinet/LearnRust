use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};

/// Adds headers that stop a browser from rendering or executing this
/// API's JSON responses as HTML/script, even if a client is tricked
/// into navigating to one directly.
pub async fn xss_layer(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();

    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));

    res
}

#[cfg(test)]
mod tests {
    use crate::xss;
    use axum::{Router, middleware, routing::get};
    use axum_test::TestServer;

    fn test_server() -> TestServer {
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(middleware::from_fn(xss::xss_layer));
        TestServer::new(app)
    }

    /// Verifies every hardened header is present on the response.
    #[test_log::test(tokio::test)]
    async fn test_xss_layer_success() {
        let server = test_server();
        let response = server.get("/ping").await;

        response.assert_status_ok();
        response.assert_header("x-content-type-options", "nosniff");
        response.assert_header("x-frame-options", "DENY");
        response.assert_header(
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        );
        response.assert_header("referrer-policy", "no-referrer");
    }
}
