//! JWT authentication and role-based authorization for this service,
//! implemented as ordinary `axum::middleware::from_fn`/`from_fn_with_state`
//! handlers.
//!
//! Two middleware functions do the work:
//! - [`authn_layer`] verifies the `Authorization: Bearer <jwt>` header,
//!   decodes [`Claims`], looks the subject up in an in-memory [`RoleStore`],
//!   and inserts an [`AuthUser`] into the request's extensions.
//! - [`authz_layer`] reads that [`AuthUser`] back out and rejects the
//!   request if it doesn't hold the required role. It must run *after*
//!   [`authn_layer`] on the same request, since it only reads what that
//!   middleware wrote.
//!
//! # Examples
//!
//! Applying both to a sub-router (see [`AuthState::new`] and [`authz_layer`]
//! for the pieces used here):
//!
//! ```ignore
//! use axum::{middleware, routing::delete, Router};
//!
//! let items_admin_routes = Router::new()
//!     .route("/items/{id}", delete(items::delete))
//!     .layer(middleware::from_fn(|ext, req, next| {
//!         auth::authz_layer("admin", ext, req, next)
//!     }));
//!
//! let protected = Router::new()
//!     .merge(items_admin_routes)
//!     .layer(middleware::from_fn_with_state(
//!         auth::AuthState::new(&jwt_secret, roles.clone()),
//!         auth::authn_layer,
//!     ));
//! ```

use axum::{
    Extension,
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use axum_error_handler::AxumErrorResponse;
use dashmap::DashMap;
use jsonwebtoken::{DecodingKey, Validation, decode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error; 

/*
use ...

#[derive(Debug, Error, AxumErrorResponse)]
pub enum AppError {
    #[error("Failed to find or read bearer token in authorization header!")]
    #[status_code("401")]
    #[code("UNAUTHORIZED")]
    Unauthorized,

    #[error("Failed to act with sufficient privilege!")]
    #[status_code("403")]
    #[code("FORBIDDEN")]
    Forbidden,
}
#[derive(Clone)]
pub struct AuthState {
    decoding_key: DecodingKey,
    validation: Validation,
    roles: RoleStore,
}
impl AuthState {
    pub fn new(jwt_secret: &SecretString, roles: RoleStore) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(jwt_secret.expose_secret().as_bytes()),
            validation: Validation::default(),
            roles,
        }
    }
}
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: String,
    pub roles: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}
type AppResult<T> = Result<T, AppError>;
type RoleStore = Arc<DashMap<String, Vec<String>>>;
fn authn_layer(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next
) -> AppResult<Response> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    let claims = decode::<Claims>;
    let user_id = claims.claims.sub;
    let roles = ;
    req.extension_mut().insert(AuthUser {
        user_id,
        roles,
    });
    Ok(next.run(req).await)
}
fn authz_layer(
    role: &'static str,
    Extension(user): Extension<AuthUser>,
    req; Request,
    next: Next
) -> AppResult<Response> {
    if user.roles.iter().any(|r| r == role)
        Ok(next.run(req).await)
    else
        Err(AppError::Unauthorized)
}
 */

/// Errors produced while authenticating or authorizing a request.
///
/// Implements [`IntoResponse`] (via `#[derive(AxumErrorResponse)]`) so
/// it can be returned directly from [`authn_layer`] and [`authz_layer`];
/// each variant's `#[status_code]`/`#[code]` attributes determine the
/// resulting HTTP status and JSON error body.
#[derive(Debug, Error, AxumErrorResponse)]
pub enum AppError {
    /// Missing, invalid, or expired bearer token; responds
    /// with `401 Unauthorized`.
    #[error("Failed to find or read bearer token in authorization header!")]
    #[status_code("401")]
    #[code("UNAUTHORIZED")]
    Unauthorized,

    /// Bearer token is valid but the authenticated user lacks the role
    /// required for this resource; responds with `403 Forbidden`.
    #[error("Failed to act with insufficient permissions!")]
    #[status_code("403")]
    #[code("FORBIDDEN")]
    Forbidden,
}

/// JWT claims this service expects to find in a validated Bearer token.
///
/// Decoded by [`authn_layer`] via [`jsonwebtoken::decode`], which also
/// enforces the `exp` claim against the configured [`Validation`].
///
/// # Examples
///
/// ```
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Debug, Clone, Deserialize, Serialize)]
/// # struct Claims { sub: String, exp: usize }
/// let claims = Claims {
///     sub: "alice".to_string(),
///     exp: 9_999_999_999,
/// };
///
/// assert_eq!(claims.sub, "alice");
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    /// The token subject — the user id used to look roles up in the
    /// [`RoleStore`].
    pub sub: String,
    /// Standard `exp` claim: a Unix timestamp (seconds since the
    /// epoch) after which the token is no longer valid. Enforced by
    /// [`jsonwebtoken::decode`] during [`authn_layer`].
    pub exp: usize,
}

/// The authenticated identity attached to a request's extensions by
/// [`authn_layer`].
///
/// Handlers can read it back out via `Extension<AuthUser>`, and
/// [`authz_layer`] reads it to perform its role check.
///
/// # Examples
///
/// ```
/// # #[derive(Clone, Debug)]
/// # struct AuthUser { user_id: String, roles: Vec<String> }
/// let user = AuthUser {
///     user_id: "alice".to_string(),
///     roles: vec!["admin".to_string(), "user".to_string()],
/// };
///
/// assert!(user.roles.iter().any(|r| r == "admin"));
/// ```
#[derive(Clone, Debug)]
pub struct AuthUser {
    /// The JWT subject (user id) this request was authenticated as.
    pub user_id: String,
    /// Roles held by this user, as of the [`RoleStore`] lookup
    /// performed by [`authn_layer`] for this request. Not re-checked
    /// for the lifetime of the request, so role changes take effect on
    /// the next request, not the current one.
    pub roles: Vec<String>,
}

/// State captured by the [`authn_layer`] middleware: the key/rules
/// used to validate incoming tokens, and the store used to resolve
/// roles for the validated subject.
///
/// Built once at startup and passed to
/// [`middleware::from_fn_with_state`](axum::middleware::from_fn_with_state)
/// alongside [`authn_layer`].
#[derive(Clone)]
pub struct AuthState {
    /// Key used to verify a token's signature. Derived once from the
    /// app's JWT secret in [`AuthState::new`].
    decoding_key: DecodingKey,
    /// Validation rules (algorithm, required claims, clock skew, etc.)
    /// applied to every token. Currently [`Validation::default`].
    validation: Validation,
    /// Store consulted for the authenticated subject's roles.
    roles: RoleStore,
}

impl AuthState {
    /// Builds authentication state from the app's JWT signing secret
    /// and role store.
    ///
    /// `jwt_secret` is read via [`ExposeSecret::expose_secret`] only
    /// for the instant it takes to build the [`DecodingKey`] — the
    /// exposed bytes are not retained; the [`SecretString`] itself is
    /// never logged or stored in plain form by this function.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dashmap::DashMap;
    /// use secrecy::SecretString;
    /// use std::sync::Arc;
    ///
    /// let jwt_secret = SecretString::from("super-secret-demo-key".to_string());
    /// let roles = Arc::new(DashMap::new());
    ///
    /// let auth_state = auth::AuthState::new(&jwt_secret, roles);
    /// ```
    ///
    /// # Panics
    ///
    /// Does not panic. [`DecodingKey::from_secret`] accepts any byte
    /// slice (including an empty one) and cannot fail.
    pub fn new(jwt_secret: &SecretString, roles: RoleStore) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(jwt_secret.expose_secret().as_bytes()),
            validation: Validation::default(),
            roles,
        }
    }
}

/// In-memory role assignments, keyed by the JWT `sub` (user id).
///
/// This is a thread-safe, reference-counted, concurrent map, so cloning
/// a `RoleStore` is cheap and shares the same underlying data — the
/// same pattern used by [`AppStore`](crate::config::AppStore) for
/// items.
///
/// # Examples
///
/// ```
/// use dashmap::DashMap;
/// use std::sync::Arc;
///
/// let roles: Arc<DashMap<String, Vec<String>>> = Arc::new(DashMap::new());
/// roles.insert("alice".to_string(), vec!["admin".to_string()]);
///
/// assert_eq!(
///     roles.get("alice").map(|r| r.clone()),
///     Some(vec!["admin".to_string()])
/// );
/// ```
pub type RoleStore = Arc<DashMap<String, Vec<String>>>;

/// Convenience alias for results returned by items in [`auth`](self).
pub type AppResult<T> = Result<T, AppError>;

/// Authenticates an incoming request: validates its Bearer token and,
/// on success, attaches an [`AuthUser`] to the request's extensions
/// before passing it on to `next`.
///
/// Intended to be layered with
/// [`middleware::from_fn_with_state`](axum::middleware::from_fn_with_state)
/// on any (sub-)router that should require authentication; downstream
/// handlers and middleware (such as [`authz_layer`]) can then read the
/// attached [`AuthUser`].
///
/// # Examples
///
/// ```ignore
/// use axum::{middleware, Router};
///
/// let protected = Router::new()
///     // ...routes...
///     .layer(middleware::from_fn_with_state(auth_state, auth::authn_layer));
/// ```
///
/// # Errors
///
/// Returns [`AppError::Unauthorized`] if the `Authorization` header is
/// missing, is not a valid UTF-8 string, does not start with
/// `"Bearer "`, or if the token fails to decode or validate (bad
/// signature, malformed claims, or an expired `exp`).
///
/// # Panics
///
/// Does not panic.
pub async fn authn_layer(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> AppResult<Response> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;

    let claims = decode::<Claims>(token, &state.decoding_key, &state.validation)
        .map_err(|_| AppError::Unauthorized)?;

    let user_id = claims.claims.sub;
    
    let roles = state
        .roles
        .get(&user_id)
        .map(|entry| entry.clone())
        .unwrap_or_default();

    req.extensions_mut().insert(AuthUser {
        user_id,
        roles,
    });

    Ok(next.run(req).await)
}

/// Rejects a request unless the [`AuthUser`] attached by
/// [`authn_layer`] holds `role`.
///
/// Must run *after* [`authn_layer`] on the same request — it only
/// reads the [`AuthUser`] that middleware wrote, and does not itself
/// validate the token.
///
/// Because [`middleware::from_fn`](axum::middleware::from_fn) expects a
/// fixed function signature, `role` is supplied by wrapping this
/// function in a closure per call site rather than partially applying
/// it directly (see the module-level example).
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] if the authenticated user's roles do
/// not include `role`.
///
/// # Panics
///
/// Does not panic.
pub async fn authz_layer(
    role: &'static str,
    Extension(user): Extension<AuthUser>,
    req: Request,
    next: Next,
) -> AppResult<Response> {
    if user.roles.iter().any(|r| r == role) {
        Ok(next.run(req).await)
    } else {
        Err(AppError::Forbidden)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthState, AuthUser, Claims, RoleStore, authn_layer, authz_layer};
    use axum::{Router, extract::Extension, http::StatusCode, middleware, routing::get};
    use axum_test::TestServer;
    use dashmap::DashMap;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use secrecy::SecretString;
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    const TEST_SECRET: &str = "test-only-secret-do-not-use-in-prod";

    /// Encodes a test JWT for `sub`, valid for one hour from now — or,
    /// if `expired` is true, expired one hour ago.
    fn mint_token(sub: &str, expired: bool) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let exp = if expired { now - 3600 } else { now + 3600 };

        let claims = Claims {
            sub: sub.to_string(),
            exp,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .unwrap()
    }

    /// A minimal protected router: `authn_layer` guards everything,
    /// and `/admin` additionally requires the "admin" role via
    /// `authz_layer`. Seeded with "alice" (admin + user) and "bob"
    /// (user only).
    fn test_server() -> TestServer {
        let roles: RoleStore = Arc::new(DashMap::new());
        roles.insert(
            "alice".to_string(),
            vec!["admin".to_string(), "user".to_string()],
        );
        roles.insert("bob".to_string(), vec!["user".to_string()]);

        let auth_state = AuthState::new(&SecretString::from(TEST_SECRET.to_string()), roles);

        let admin_only = Router::new()
            .route("/admin", get(|| async { "admin ok" }))
            .layer(middleware::from_fn(|ext, req, next| {
                authz_layer("admin", ext, req, next)
            }));

        let app = Router::new()
            .route(
                "/me",
                get(|Extension(user): Extension<AuthUser>| async move { user.user_id }),
            )
            .merge(admin_only)
            .layer(middleware::from_fn_with_state(
                auth_state,
                authn_layer,
            ));

        TestServer::new(app)
    }

    /// Verifies a valid token authenticates and `AuthUser` is extractable.
    #[test_log::test(tokio::test)]
    async fn test_authenticate_success() {
        let server = test_server();
        let token = mint_token("alice", false);

        let response = server
            .get("/me")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::OK);
        response.assert_text("alice");
    }

    /// Verifies a missing `Authorization` header is rejected.
    #[test_log::test(tokio::test)]
    async fn test_authenticate_failure_missing_header() {
        let response = test_server().get("/me").await;
        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    /// Verifies a header without a `Bearer ` prefix is rejected.
    #[test_log::test(tokio::test)]
    async fn test_authenticate_failure_invalid_header() {
        let response = test_server()
            .get("/me")
            .add_header(axum::http::header::AUTHORIZATION, "not-a-bearer-token")
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    /// Verifies a token signed with a different secret is rejected.
    #[test_log::test(tokio::test)]
    async fn test_authenticate_failure_invalid_token() {
        let claims = Claims {
            sub: "alice".to_string(),
            exp: usize::MAX,
        };
        let bad_token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"wrong-secret"),
        )
        .unwrap();

        let response = test_server()
            .get("/me")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {bad_token}"),
            )
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    /// Verifies an expired token is rejected.
    #[test_log::test(tokio::test)]
    async fn test_authenticate_failure_expired_token() {
        let token = mint_token("alice", true);

        let response = test_server()
            .get("/me")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    /// Verifies a user holding the required role is allowed through.
    #[test_log::test(tokio::test)]
    async fn test_authorize_success() {
        let token = mint_token("alice", false); // alice: admin, user

        let response = test_server()
            .get("/admin")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::OK);
    }

    /// Verifies an authenticated user lacking the required role is
    /// forbidden.
    #[test_log::test(tokio::test)]
    async fn test_authorize_failure_forbidden() {
        let token = mint_token("bob", false); // bob: user only

        let response = test_server()
            .get("/admin")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::FORBIDDEN);
    }

    /// Verifies a valid token for a subject with no `RoleStore` entry
    /// at all is treated as having zero roles, not an error.
    #[test_log::test(tokio::test)]
    async fn test_authorize_failure_unknown_user_has_no_roles() {
        let token = mint_token("mallory", false); // not seeded in RoleStore

        let response = test_server()
            .get("/admin")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::FORBIDDEN);
    }
}
