//! JWT authentication helpers.
//!
//! This module exposes:
//! - [`Claims`] — the JWT payload, carrying a user id (`sub`) and their
//!   [`Vec<String>`] of roles.
//! - [`JwtAuthLayer`] — a [`tower::Layer`] that extracts and validates the
//!   `Authorization: Bearer <token>` header on every request, attaching the
//!   decoded [`Claims`] to the request's extensions.
//! - [`generate_token`] — helper used by the login endpoint to mint a new
//!   signed JWT for a given user id and set of roles.
//! - [`JwtError`] — the error type returned by the layer when the token is
//!   missing, malformed, or expired.

use axum::{
    async_trait,
    extract::{FromRequestParts, FromRef},
    http::{request::Parts, HeaderMap, StatusCode},
    response::IntoResponse,
};
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// JWT payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the user id this token was issued for.
    pub sub: String,
    /// Roles granted to the subject (e.g. `["admin"]`).
    pub roles: Vec<String>,
    /// Expiration time, in seconds since the Unix epoch.
    pub exp: usize,
}

/// Errors that can occur while authenticating a request.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// No `Authorization` header was present, or it did not start with
    /// `Bearer `.
    #[error("Missing or malformed Authorization header!")]
    MissingToken,

    /// The JWT signature could not be verified, or the token was malformed.
    #[error("Invalid token! {0}")]
    InvalidToken(#[from] jsonwebtoken::errors::Error),

    /// The token is missing a required claim.
    #[error("Token is missing required claims! {0}")]
    MissingClaims(String),
}

impl IntoResponse for JwtError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            JwtError::MissingToken => StatusCode::UNAUTHORIZED,
            JwtError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            JwtError::MissingClaims(_) => StatusCode::BAD_REQUEST,
        };

        let body = axum::Json(serde_json::json!({
            "status": self.to_string(),
        }));

        (status, body).into_response()
    }
}

/// A [`tower::Layer`] that validates the `Authorization: Bearer <token>`
/// header on every request and attaches the decoded [`Claims`] to the
/// request's extensions so handlers can extract them via
/// [`axum::extract::Extension<Claims>`].
#[derive(Clone)]
pub struct JwtAuthLayer {
    secret: Arc<SecretString>,
}

impl JwtAuthLayer {
    /// Build a new JWT auth layer from a shared secret.
    pub fn new(secret: SecretString) -> Self {
        Self {
            secret: Arc::new(secret),
        }
    }
}

impl<S, B> tower::Layer<S> for JwtAuthLayer
where
    S: Service<Request = axum::http::Request<B>, Response = axum::response::Response>,
    S::Future: Send + 'static,
    B: axum::body::Body + Send + 'static,
    B::Data: Send + 'static,
{
    type Response = S::Response;
    type Error = JwtError;
    type Transform = JwtAuthMiddleware<S>;
    type InitError = ();
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_layer(&self, inner: S) -> Self::Future {
        std::future::ready(Ok(JwtAuthMiddleware {
            inner,
            secret: self.secret.clone(),
        }))
    }
}

/// The middleware service produced by [`JwtAuthLayer`].
#[derive(Clone)]
pub struct JwtAuthMiddleware<S> {
    inner: S,
    secret: Arc<SecretString>,
}

impl<S, B> tower::Service<axum::http::Request<B>> for JwtAuthMiddleware<S>
where
    S: tower::Service<Request = axum::http::Request<B>, Response = axum::response::Response>,
    S::Future: Send + 'static,
    B: axum::body::Body + Send + 'static,
    B::Data: Send + 'static,
{
    type Response = S::Response;
    type Error = JwtError;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        std::task::Poll::Ready(())
    }

    fn call(&mut self, req: axum::http::Request<B>) -> Self::Future {
        let secret = self.secret.clone();
        let (parts, body) = req.into_parts();

        let result = extract_claims(&parts.headers, &secret).map(|claims| {
            let mut req = axum::http::Request::from_parts(parts, body);
            req.extensions_mut().insert(claims);
            req
        });

        match result {
            Ok(req) => {
                let fut = self.inner.call(req);
                std::future::ready(Ok(fut))
            }
            Err(err) => std::future::ready(Err(err)),
        }
    }
}

/// Extract and decode the JWT from the request headers.
fn extract_claims(headers: &HeaderMap, secret: &SecretString) -> Result<Claims, JwtError> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(JwtError::MissingToken)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(JwtError::MissingToken)?;

    let mut validation = Validation::default();
    validation.validate_exp = true;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.expose_secret().as_bytes()),
        &validation,
    )?;

    Ok(token_data.claims)
}

/// Mint a new signed JWT for the given subject and roles.
///
/// The token expires after `expires_in_seconds` seconds from now.
pub fn generate_token(
    sub: impl Into<String>,
    roles: Vec<String>,
    expires_in_seconds: usize,
    secret: &SecretString,
) -> Result<String, jsonwebtoken::errors::Error> {
    use jsonwebtoken::{encode, Header, EncodingKey};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();

    let claims = Claims {
        sub: sub.into(),
        roles,
        exp: (now.as_secs() as usize).saturating_add(expires_in_seconds),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.expose_secret().as_bytes()),
    )
}

/// A convenient extractor that pulls the decoded [`Claims`] out of the
/// request extensions, so handlers can use `Extension<Claims>` directly.
impl<S, B> FromRequestParts<S> for Claims
where
    S: Send + Sync,
    B: axum::body::Body,
{
    type Rejection = JwtError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .ok_or_else(|| JwtError::MissingClaims("Claims not found in request extensions!".into()))
    }
}

/// Re-export the `secrecy::SecretString` type so callers can build the layer
/// without importing `secrecy` directly.
pub use secrecy::SecretString;