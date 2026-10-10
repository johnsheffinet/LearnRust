//! JWT authentication, role-based authorization, and self-service token
//! lifecycle (issue, renew, revoke) for this service.
//!
//! # Middleware
//!
//! - [`authn_layer`] verifies the `Authorization: Bearer <jwt>` header,
//!   decodes [`Claims`], checks the token's `ver` against the version
//!   recorded in the [`TokenStore`] (rejecting renewed/revoked tokens),
//!   looks the subject up in a [`RoleStore`], and inserts an [`AuthUser`]
//!   into the request's extensions.
//! - [`authz_layer`] reads that [`AuthUser`] back out and rejects the
//!   request if it doesn't hold the required role. It must run *after*
//!   [`authn_layer`] on the same request, since it only reads what that
//!   middleware wrote.
//!
//! # Token lifecycle
//!
//! A bare JWT cannot be updated or revoked, so every token carries a `ver`
//! (version) claim. The [`TokenStore`] records the current version per
//! user; [`authn_layer`] rejects any token whose `ver` doesn't match. That
//! makes three self-service operations well-defined, all at `/auth/token`
//! and all scoped to the caller (they sit inside the [`authn_layer`]
//! group, so the caller must already hold a valid token):
//!
//! - [`issue_token`] (`POST /auth/token`): mints a fresh token for the
//!   caller at their *current* version. Previously issued tokens remain
//!   valid — additive, useful for a second device.
//! - [`renew_token`] (`PUT /auth/token`): bumps the caller's version,
//!   immediately invalidating every token they previously held, and
//!   returns one replacement at the new version.
//! - [`revoke_token`] (`DELETE /auth/token`): bumps the caller's version
//!   without issuing a replacement, killing all the caller's tokens.
//!
//! Bootstrapping the very first token for a user is deliberately *not* an
//! HTTP endpoint. An unauthenticated "mint me a token" route is a
//! privilege-escalation hole, and the authenticated operations above all
//! require a token to call — so the first one has to come from somewhere
//! else. Seed it out-of-band (a startup task, a CLI subcommand, or your
//! real identity provider).
//!
//! Role assignments are stored separately in the [`RoleStore`] and are not
//! embedded in the token; a token's authority is whatever the store says
//! about its subject when the token is presented, so a role change takes
//! effect on the subject's next request.
//!
//! # Examples
//!
//! Applying the middleware and lifecycle routes:
//!
//! ```ignore
//! use axum::{middleware, routing::{post, put, delete}, Router};
//!
//! let token_routes = Router::new().route(
//!     "/auth/token",
//!     post(auth::issue_token).put(auth::renew_token).delete(auth::revoke_token),
//! );
//!
//! let protected = Router::new()
//!     .merge(token_routes)
//!     .layer(middleware::from_fn_with_state(
//!         auth::AuthState::new(&jwt_secret, roles.clone(), tokens.clone())?,
//!         auth::authn_layer,
//!     ));
//! ```

use axum::{
    Extension, Json,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_error_handler::AxumErrorResponse;
use dashmap::DashMap;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Errors produced while authenticating, authorizing, or managing tokens.
///
/// Implements [`IntoResponse`] (via `#[derive(AxumErrorResponse)]`) so it
/// can be returned directly from the middleware and handlers in this
/// module; each variant's `#[status_code]`/`#[code]` attributes determine
/// the resulting HTTP status and JSON error body.
#[derive(Debug, Error, AxumErrorResponse)]
pub enum AppError {
    /// Missing, malformed, invalid/expired, or renewed/revoked bearer
    /// token; responds with `401 Unauthorized`.
    ///
    /// Renewed/revoked tokens (wrong `ver`) deliberately map to the same
    /// opaque error as malformed ones, so a caller cannot distinguish
    /// "your token was renewed elsewhere" from "your token was never
    /// valid".
    #[error("Failed to read bearer token!")]
    #[status_code("401")]
    #[code("UNAUTHORIZED")]
    Unauthorized,

    /// Token is valid but the authenticated user lacks the role required
    /// for this resource; responds with `403 Forbidden`.
    #[error("Failed with inadequate role!")]
    #[status_code("403")]
    #[code("FORBIDDEN")]
    Forbidden,

    /// The JWT could not be signed. Practically unreachable with HMAC
    /// secrets, but surfaced rather than `panic!`ed so a bad configuration
    /// cannot take down a worker. Responds with `500 Internal Server Error`.
    #[error("Failed to sign token! {0}")]
    #[status_code("500")]
    #[code("INTERNAL_SERVER_ERROR")]
    InternalServerError(#[from] jsonwebtoken::errors::Error),

    /// The computed `exp` for a new token overflowed the clock, or the
    /// configured lifetime truncated to zero. Responds with
    /// `422 Unprocessable Entity` when reached from a request; when
    /// returned by [`AuthState::with_ttl`] it is a startup-time
    /// configuration failure.
    #[error("Failed to set expiry in bearer token!")]
    #[status_code("422")]
    #[code("UNPROCESSABLE_ENTITY")]
    UnprocessableEntity,
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// The authenticated identity attached to a request's extensions by
/// [`authn_layer`].
///
/// Handlers can read it back out via `Extension<AuthUser>`; [`authz_layer`]
/// reads it to perform its role check, and the lifecycle handlers read
/// `user_id` to know whose tokens to rotate or revoke.
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
    /// Roles held by this user, as of the [`RoleStore`] lookup performed
    /// by [`authn_layer`] for this request. Not re-checked for the
    /// lifetime of the request, so role changes take effect on the next
    /// request, not the current one.
    pub roles: Vec<String>,
}

/// State captured by the [`authn_layer`] middleware and shared with the
/// lifecycle handlers: the keys used to sign and verify tokens, the
/// validation rules, the role store, the token store, and the lifetime
/// assigned to newly minted tokens.
///
/// Built once at startup and passed to
/// [`middleware::from_fn_with_state`](axum::middleware::from_fn_with_state)
/// alongside [`authn_layer`].
#[derive(Clone)]
pub struct AuthState {
    /// Key used to verify a token's signature. Derived once from the
    /// app's JWT secret in [`AuthState::new`].
    decoding_key: DecodingKey,
    /// Key used to sign tokens minted by [`issue_token`] and
    /// [`renew_token`]. Derived from the same secret as `decoding_key`.
    encoding_key: EncodingKey,
    /// Validation rules (algorithm, required claims, clock skew, etc.)
    /// applied to every token. Currently [`Validation::default`].
    validation: Validation,
    /// Store consulted for the authenticated subject's roles.
    roles: RoleStore,
    /// Store consulted for the subject's current token version, and
    /// updated by the lifecycle handlers.
    tokens: TokenStore,
    /// Lifetime of tokens minted by this service, in seconds.
    token_ttl: u64,
}

impl AuthState {
    /// Builds authentication state from the app's JWT signing secret, role
    /// store, and token store.
    ///
    /// `jwt_secret` is read via [`ExposeSecret::expose_secret`] only for
    /// the instant it takes to build the keys — the exposed bytes are not
    /// retained; the [`SecretString`] itself is never logged or stored in
    /// plain form by this function.
    ///
    /// Tokens minted through this state live for one hour.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::UnprocessableEntity`] only if the one-hour
    /// default is invalid, which cannot happen — the `Result` is returned
    /// so callers can `?` it uniformly with [`AuthState::with_ttl`].
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
    /// let tokens = Arc::new(DashMap::new());
    ///
    /// let auth_state = auth::AuthState::new(&jwt_secret, roles, tokens)?;
    /// ```
    ///
    /// # Panics
    ///
    /// Does not panic. `DecodingKey::from_secret` /
    /// `EncodingKey::from_secret` accept any byte slice (including an empty
    /// one) and cannot fail.
    pub fn new(jwt_secret: &SecretString, roles: RoleStore, tokens: TokenStore) -> AppResult<Self> {
        Self::with_ttl(jwt_secret, roles, tokens, Duration::from_secs(60 * 60))
    }

    /// Signs a token for `sub` at the given version, returning the encoded
    /// JWT and the `jti` embedded in it.
    fn sign(&self, sub: &str, ver: u64) -> AppResult<(String, String)> {
        let jti = Uuid::new_v4().to_string();

        let claims = Claims {
            sub: sub.to_string(),
            exp: exp_from_ttl(self.token_ttl)?,
            jti: jti.clone(),
            ver,
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;

        Ok((token, jti))
    }

    /// Like [`AuthState::new`], but with an explicit token lifetime.
    ///
    /// Exposed mainly so tests can mint short-lived tokens without
    /// sleeping.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::UnprocessableEntity`] if `token_ttl` truncates
    /// to zero seconds. A zero lifetime produces a token whose `exp`
    /// equals its mint time, which [`jsonwebtoken::decode`] rejects as
    /// already expired — so the token would be dead on arrival, and a
    /// caller passing a sub-second duration almost certainly meant
    /// something else. Rejecting it here turns a confusing runtime `401`
    /// into a clear configuration failure.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn with_ttl(
        jwt_secret: &SecretString,
        roles: RoleStore,
        tokens: TokenStore,
        token_ttl: Duration,
    ) -> AppResult<Self> {
        // Check the truncated value, not the `Duration` itself: a
        // sub-second duration is not zero, but `as_secs()` on it is.
        let token_ttl = token_ttl.as_secs();
        if token_ttl == 0 {
            return Err(AppError::UnprocessableEntity);
        }

        let secret = jwt_secret.expose_secret().as_bytes();

        Ok(Self {
            decoding_key: DecodingKey::from_secret(secret),
            encoding_key: EncodingKey::from_secret(secret),
            validation: Validation::default(),
            roles,
            tokens,
            token_ttl,
        })
    }
}

/// JWT claims this service expects to find in a validated Bearer token.
///
/// Decoded by [`authn_layer`] via [`jsonwebtoken::decode`], which also
/// enforces the `exp` claim against the configured [`Validation`].
///
/// The `jti` and `ver` claims make the otherwise-stateless JWT revocable:
/// see the module-level "Token lifecycle" docs.
///
/// # Examples
///
/// ```
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Debug, Clone, Deserialize, Serialize)]
/// # struct Claims { sub: String, exp: usize, jti: String, ver: u64 }
/// let claims = Claims {
///     sub: "alice".to_string(),
///     exp: 9_999_999_999,
///     jti: "0b6f...".to_string(),
///     ver: 1,
/// };
///
/// assert_eq!(claims.sub, "alice");
/// assert_eq!(claims.ver, 1);
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    /// The token subject — the user id used to look roles up in the
    /// [`RoleStore`] and the version up in the [`TokenStore`].
    pub sub: String,
    /// Standard `exp` claim: a Unix timestamp (seconds since the epoch)
    /// after which the token is no longer valid. Enforced by
    /// [`jsonwebtoken::decode`] during [`authn_layer`].
    pub exp: usize,
    /// Standard `jti` claim: a unique identifier for this specific token.
    /// Not used for lookup — carried so tokens are distinguishable in logs
    /// and so a per-token denylist could be added later without a
    /// wire-format change.
    pub jti: String,
    /// This service's revocation generation for `sub`. [`authn_layer`]
    /// rejects the token unless it matches the version currently recorded
    /// in the [`TokenStore`].
    pub ver: u64,
}

/// Per-user token revocation state.
///
/// `version` is the current generation; any token carrying a different
/// `ver` is rejected by [`authn_layer`]. Bumping it revokes every
/// outstanding token for that user at once — this is what [`renew_token`]
/// and [`revoke_token`] do.
///
/// `active_jti` records the `jti` of the most recently minted token, if
/// any. It is purely informational: the `ver` check is what enforces
/// revocation, and `active_jti` exists only so [`revoke_token`] can echo
/// which token it killed and so a future "list my sessions" endpoint has
/// something to read.
#[derive(Clone, Debug, Default)]
pub struct TokenState {
    /// The current revocation generation for this user.
    pub version: u64,
    /// The `jti` of the newest token minted for this user, if any.
    pub active_jti: Option<String>,
}

/// Response body for the token-lifecycle handlers.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenResponse {
    /// The encoded JWT. Present on [`issue_token`] and [`renew_token`];
    /// absent on [`revoke_token`], which issues no replacement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// The `jti` of the token that was minted (or, for revoke, the most
    /// recently active one that was invalidated).
    pub jti: String,
    /// The `ver` claim now in force for the caller.
    pub ver: u64,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Convenience alias for results returned by items in [`auth`](self).
pub type AppResult<T> = Result<T, AppError>;

/// In-memory role assignments, keyed by the JWT `sub` (user id).
///
/// This is a thread-safe, reference-counted, concurrent map, so cloning a
/// `RoleStore` is cheap and shares the same underlying data — the same
/// pattern used by [`AppStore`](crate::config::AppStore) for items.
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

/// In-memory token revocation state, keyed by the JWT `sub` (user id).
///
/// Like [`RoleStore`], this is a thread-safe, reference-counted, concurrent
/// map, so cloning a `TokenStore` is cheap and shares the same underlying
/// data.
///
/// Memory use is O(distinct users), not O(issued tokens): rotation reuses
/// a single counter rather than retaining a per-token denylist.
pub type TokenStore = Arc<DashMap<String, TokenState>>;

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// Authenticates an incoming request: validates its Bearer token, confirms
/// it hasn't been renewed or revoked, and, on success, attaches an
/// [`AuthUser`] to the request's extensions before passing it on to `next`.
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
/// missing, is not a valid UTF-8 string, does not start with `"Bearer "`,
/// if the token fails to decode or validate (bad signature, malformed
/// claims, or an expired `exp`), or if the token's `ver` does not match the
/// subject's current version in the [`TokenStore`] (i.e. it was renewed or
/// revoked).
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

    let token_data = decode::<Claims>(token, &state.decoding_key, &state.validation)
        .map_err(|_| AppError::Unauthorized)?;

    let current_ver = state
        .tokens
        .get(&token_data.claims.sub)
        .map(|entry| entry.version)
        .unwrap_or(0);

    if token_data.claims.ver != current_ver {
        return Err(AppError::Unauthorized);
    }

    let roles = state
        .roles
        .get(&token_data.claims.sub)
        .map(|entry| entry.clone())
        .unwrap_or_default();

    req.extensions_mut().insert(AuthUser {
        user_id: token_data.claims.sub,
        roles,
    });

    Ok(next.run(req).await)
}

/// Rejects a request unless the [`AuthUser`] attached by [`authn_layer`]
/// holds `role`.
///
/// Must run *after* [`authn_layer`] on the same request — it only reads the
/// [`AuthUser`] that middleware wrote, and does not itself validate the
/// token.
///
/// Because [`middleware::from_fn`](axum::middleware::from_fn) expects a
/// fixed function signature, `role` is supplied by wrapping this function
/// in a closure per call site rather than partially applying it directly
/// (see the module-level example).
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] if the authenticated user's roles do not
/// include `role`.
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

/// Computes the `exp` claim for a token minted now, given a lifetime in
/// seconds, as a Unix timestamp.
///
/// Returns [`AppError::UnprocessableEntity`] if the system clock is before
/// the epoch or the addition overflows `u64`.
///
/// Factored out of [`AuthState::sign`] so the `exp` math is a pure function
/// of the clock and a duration, testable without constructing an
/// [`AuthState`].
fn exp_from_ttl(token_ttl: u64) -> AppResult<usize> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::UnprocessableEntity)?
        .as_secs();

    now.checked_add(token_ttl)
        .map(|exp| exp as usize)
        .ok_or(AppError::UnprocessableEntity)
}

/// Handles `POST /auth/token`: issues a fresh token for the caller.
///
/// The new token carries the caller's *current* version, so any tokens
/// they already hold stay valid — issuing is additive. Use
/// [`renew_token`] instead when the point is to invalidate the old ones.
///
/// Requires a valid bearer token to call, since it mints a token for
/// whoever the request authenticated as.
///
/// # Errors
///
/// Returns [`AppError::InternalServerError`] if the token cannot be signed, or
/// [`AppError::UnprocessableEntity`] if the computed `exp` overflows.
///
/// # Panics
///
/// Does not panic.
pub async fn issue_token(
    State(state): State<AuthState>,
    Extension(user): Extension<AuthUser>,
) -> AppResult<impl IntoResponse> {
    let ver = state
        .tokens
        .get(&user.user_id)
        .map(|entry| entry.version)
        .unwrap_or(0);

    let (token, jti) = state.sign(&user.user_id, ver)?;

    state
        .tokens
        .entry(user.user_id)
        .or_default()
        .active_jti = Some(jti.clone());

    Ok((
        StatusCode::CREATED,
        Json(TokenResponse {
            token: Some(token),
            jti,
            ver,
        }),
    ))
}

/// Handles `PUT /auth/token`: renews the caller's token.
///
/// Bumps the caller's version, which immediately invalidates every token
/// previously issued to them, then mints and returns a replacement at the
/// new version.
///
/// # Errors
///
/// Returns [`AppError::InternalServerError`] or
/// [`AppError::UnprocessableEntity`] under the same conditions as
/// [`issue_token`].
///
/// # Panics
///
/// Does not panic.
pub async fn renew_token(
    State(state): State<AuthState>,
    Extension(user): Extension<AuthUser>,
) -> AppResult<impl IntoResponse> {
    let mut entry = state.tokens.entry(user.user_id.clone()).or_default();

    let ver = entry.version.saturating_add(1);
    let (token, jti) = state.sign(&user.user_id, ver)?;

    entry.version = ver;
    entry.active_jti = Some(jti.clone());

    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            token: Some(token),
            jti,
            ver,
        }),
    ))
}

/// Handles `DELETE /auth/token`: revokes the caller's tokens.
///
/// Bumps the caller's version without issuing a replacement, so every
/// token they currently hold is rejected by [`authn_layer`] on its next
/// use.
///
/// The response echoes the `jti` that was most recently active, if any,
/// purely for the caller's own logging; the revocation itself is the
/// version bump, not the `jti`.
///
/// # Errors
///
/// Does not currently fail; returns [`AppResult`] so a future persistent
/// backing store can surface write failures without a signature change.
///
/// # Panics
///
/// Does not panic.
pub async fn revoke_token(
    State(state): State<AuthState>,
    Extension(user): Extension<AuthUser>,
) -> AppResult<impl IntoResponse> {
    let mut entry = state.tokens.entry(user.user_id.clone()).or_default();

    let ver = entry.version.saturating_add(1);
    let jti = entry.active_jti.take().unwrap_or_default();
    entry.version = ver;

    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            token: None,
            jti,
            ver,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        AuthState, AuthUser, Claims, RoleStore, TokenResponse, TokenState, TokenStore, authn_layer,
        authz_layer, exp_from_ttl, issue_token, renew_token, revoke_token,
    };
    use axum::{
        Extension, Router,
        http::StatusCode,
        middleware,
        routing::{delete, get, post, put},
    };
    use axum_test::TestServer;
    use dashmap::DashMap;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use secrecy::SecretString;
    use serde_json::Value;
    use std::{
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use uuid::Uuid;

    const TEST_SECRET: &str = "test-only-secret-do-not-use-in-prod";

    /// Seeds a `TokenStore` with the given users at version 1, matching
    /// what a first `issue_token` would have produced, and returns it.
    fn seeded_tokens(users: &[&str]) -> TokenStore {
        let tokens: TokenStore = Arc::new(DashMap::new());
        for user in users {
            tokens.insert(
                user.to_string(),
                TokenState {
                    version: 1,
                    active_jti: None,
                },
            );
        }
        tokens
    }

    /// Encodes a test JWT for `sub` at `ver`, valid for one hour from now —
    /// or, if `expired` is true, expired one hour ago.
    fn mint_token(sub: &str, ver: u64, expired: bool) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let exp = if expired { now - 3600 } else { now + 3600 };

        let claims = Claims {
            sub: sub.to_string(),
            exp,
            jti: Uuid::new_v4().to_string(),
            ver,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .unwrap()
    }

    fn auth_state(roles: RoleStore, tokens: TokenStore) -> AuthState {
        AuthState::with_ttl(
            &SecretString::from(TEST_SECRET.to_string()),
            roles,
            tokens,
            Duration::from_secs(3600),
        )
        .unwrap()
    }

    /// A minimal router exercising both middleware and all three lifecycle
    /// handlers, plus a `/me` probe and an admin-only `/admin` probe.
    /// Seeded with "alice" (admin + user, ver 1) and "bob" (user only,
    /// ver 1).
    fn test_server() -> TestServer {
        let roles: RoleStore = Arc::new(DashMap::new());
        roles.insert(
            "alice".to_string(),
            vec!["admin".to_string(), "user".to_string()],
        );
        roles.insert("bob".to_string(), vec!["user".to_string()]);

        let tokens = seeded_tokens(&["alice", "bob"]);
        let state = auth_state(roles, tokens);

        let token_routes = Router::new().route(
            "/auth/token",
            post(issue_token).put(renew_token).delete(revoke_token),
        );

        let admin_only = Router::new()
            .route("/admin", get(|| async { "admin ok" }))
            .layer(middleware::from_fn(|ext, req, next| {
                authz_layer("admin", ext, req, next)
            }));

        let me = Router::new().route(
            "/me",
            get(|Extension(user): Extension<AuthUser>| async move { user.user_id }),
        );

        let app = Router::new()
            .merge(token_routes)
            .merge(admin_only)
            .merge(me)
            .layer(middleware::from_fn_with_state(state, authn_layer));

        TestServer::new(app)
    }

    // ---- exp_from_ttl ----

    /// Verifies `exp_from_ttl` produces a timestamp roughly `token_ttl`
    /// seconds in the future.
    #[test_log::test(tokio::test)]
    async fn test_exp_from_ttl_success() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let exp = exp_from_ttl(3600).unwrap();

        // Allow a wide window so the test isn't clock-sensitive.
        assert!(exp > now + 3500);
        assert!(exp <= now + 3600);
    }

    // ---- authn / authz ----

    /// Verifies a valid token authenticates and `AuthUser` is extractable.
    #[test_log::test(tokio::test)]
    async fn test_authenticate_success() {
        let server = test_server();
        let token = mint_token("alice", 1, false);

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
            jti: Uuid::new_v4().to_string(),
            ver: 1,
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
        let token = mint_token("alice", 1, true);

        let response = test_server()
            .get("/me")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    /// Verifies a token whose `ver` is behind the store's is rejected —
    /// the core of revocation.
    #[test_log::test(tokio::test)]
    async fn test_authenticate_failure_stale_version() {
        let token = mint_token("alice", 0, false); // store says 1

        let response = test_server()
            .get("/me")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    /// Verifies a valid token for a subject with no `TokenStore` entry at
    /// all is treated as version 0, not an error.
    #[test_log::test(tokio::test)]
    async fn test_authenticate_success_unknown_user_version_zero() {
        let token = mint_token("newcomer", 0, false); // not in TokenStore

        let response = test_server()
            .get("/me")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::OK);
        response.assert_text("newcomer");
    }

    /// Verifies a user holding the required role is allowed through.
    #[test_log::test(tokio::test)]
    async fn test_authorize_success() {
        let token = mint_token("alice", 1, false); // alice: admin, user

        let response = test_server()
            .get("/admin")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::OK);
        response.assert_text("admin ok");
    }

    /// Verifies an authenticated user lacking the required role is
    /// forbidden.
    #[test_log::test(tokio::test)]
    async fn test_authorize_failure_forbidden() {
        let token = mint_token("bob", 1, false); // bob: user only

        let response = test_server()
            .get("/admin")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::FORBIDDEN);
    }

    /// Verifies a valid token for a subject with no `RoleStore` entry at
    /// all is treated as having zero roles, not an error.
    #[test_log::test(tokio::test)]
    async fn test_authorize_failure_unknown_user_has_no_roles() {
        let token = mint_token("mallory", 0, false); // not seeded in RoleStore

        let response = test_server()
            .get("/admin")
            .add_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .await;

        response.assert_status(StatusCode::FORBIDDEN);
    }

    // ---- lifecycle: issue ----

    /// Verifies `POST /auth/token` returns a working token at the caller's
    /// current version, and leaves previously issued tokens valid.
    #[test_log::test(tokio::test)]
    async fn test_issue_token_success_additive() {
        let server = test_server();
        let existing = mint_token("alice", 1, false);

        let response = server
            .post("/auth/token")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {existing}"),
            )
            .await;

        response.assert_status(StatusCode::CREATED);

        let TokenResponse { token, jti, ver } = response.json();
        assert_eq!(ver, 1);
        assert!(!jti.is_empty());

        let new_token = token.expect("issue must return a token");

        // The freshly issued token works...
        server
            .get("/me")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {new_token}"),
            )
            .await
            .assert_status(StatusCode::OK)
            .assert_text("alice");

        // ...and the one used to call the endpoint still works too,
        // because issuing didn't bump the version.
        server
            .get("/me")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {existing}"),
            )
            .await
            .assert_status(StatusCode::OK);
    }

    /// Verifies `POST /auth/token` without a bearer token is rejected —
    /// lifecycle endpoints require the caller to already be authenticated.
    #[test_log::test(tokio::test)]
    async fn test_issue_token_failure_unauthenticated() {
        let response = test_server().post("/auth/token").await;
        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    // ---- lifecycle: renew ----

    /// Verifies `PUT /auth/token` returns a working token at a bumped
    /// version and invalidates the token used to call it.
    #[test_log::test(tokio::test)]
    async fn test_renew_token_success_invalidates_previous() {
        let server = test_server();
        let existing = mint_token("alice", 1, false);

        let response = server
            .put("/auth/token")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {existing}"),
            )
            .await;

        response.assert_status(StatusCode::OK);

        let TokenResponse { token, ver, .. } = response.json();
        assert_eq!(ver, 2);
        let renewed = token.expect("renew must return a token");

        // The renewed token works...
        server
            .get("/me")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {renewed}"),
            )
            .await
            .assert_status(StatusCode::OK);

        // ...and the one used to call the endpoint is now dead.
        server
            .get("/me")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {existing}"),
            )
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }

    /// Verifies `PUT /auth/token` without a bearer token is rejected.
    #[test_log::test(tokio::test)]
    async fn test_renew_token_failure_unauthenticated() {
        let response = test_server().put("/auth/token").await;
        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    // ---- lifecycle: revoke ----

    /// Verifies `DELETE /auth/token` bumps the version, returns no token,
    /// and kills the token used to call it.
    #[test_log::test(tokio::test)]
    async fn test_revoke_token_success_invalidates_previous() {
        let server = test_server();
        let existing = mint_token("alice", 1, false);

        let response = server
            .delete("/auth/token")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {existing}"),
            )
            .await;

        response.assert_status(StatusCode::OK);

        let TokenResponse { token, ver, .. } = response.json();
        assert_eq!(ver, 2);
        assert!(token.is_none(), "revoke must not return a token");

        // The token used to revoke is now dead.
        server
            .get("/me")
            .add_header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {existing}"),
            )
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }

    /// Verifies `DELETE /auth/token` without a bearer token is rejected.
    #[test_log::test(tokio::test)]
    async fn test_revoke_token_failure_unauthenticated() {
        let response = test_server().delete("/auth/token").await;
        response.assert_status(StatusCode::UNAUTHORIZED);
    }

    // ---- with_ttl guard ----

    /// Verifies `with_ttl` rejects a zero lifetime rather than minting
    /// tokens that are dead on arrival.
    #[test_log::test(tokio::test)]
    async fn test_with_ttl_failure_zero_duration() {
        let result = AuthState::with_ttl(
            &SecretString::from(TEST_SECRET.to_string()),
            Arc::new(DashMap::new()),
            Arc::new(DashMap::new()),
            Duration::ZERO,
        );

        assert!(matches!(result, Err(super::AppError::UnprocessableEntity)));
    }

    /// Verifies `with_ttl` rejects a sub-second lifetime, which truncates
    /// to zero seconds and would otherwise slip past an `is_zero()` check.
    #[test_log::test(tokio::test)]
    async fn test_with_ttl_failure_sub_second_duration() {
        let result = AuthState::with_ttl(
            &SecretString::from(TEST_SECRET.to_string()),
            Arc::new(DashMap::new()),
            Arc::new(DashMap::new()),
            Duration::from_millis(500),
        );

        assert!(matches!(result, Err(super::AppError::UnprocessableEntity)));
    }
}
