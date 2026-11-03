//! JWT authentication, role-based authorization, and self-service token
//! lifecycle (issue, renew, revoke) for this service.
//!
//! # Middleware
//!
//! - [`authn_layer`] verifies the `Authorization: Bearer <jwt>` header,
//!   decodes [`Claims`], checks the token's `ver` against the version
//!   recorded in the caller's [`User`] entry (rejecting renewed/revoked
//!   tokens), and inserts an [`AuthUser`] into the request's extensions.
//! - [`authz_layer`] reads that [`AuthUser`] back out and rejects the
//!   request if it doesn't hold the required role. It must run *after*
//!   [`authn_layer`] on the same request, since it only reads what that
//!   middleware wrote.
//!
//! # Token lifecycle
//!
//! A bare JWT cannot be updated or revoked, so every token carries a `ver`
//! (version) claim. Each user's [`User`] entry records the current version;
//! [`authn_layer`] rejects any token whose `ver` doesn't match. That makes
//! three self-service operations well-defined, all at `/auth/token` and all
//! scoped to the caller (they sit inside the [`authn_layer`] group, so the
//! caller must already hold a valid token):
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
//! Roles live on the same [`User`] entry as the version, so a single lookup
//! resolves both, and a user cannot exist in one store but not the other.
//! Role assignments are still not embedded in the token; a token's
//! authority is whatever the [`User`] entry says about its subject when the
//! token is presented, so a role change takes effect on the subject's next
//! request.
//!
//! Bootstrapping the very first user is deliberately *not* an HTTP endpoint.
//! An unauthenticated "mint me a token" route is a privilege-escalation
//! hole, and the authenticated operations above all require a token to
//! call — so the first user, their roles, and their initial token version
//! have to come from somewhere else. Seed them out-of-band (a startup task,
//! a CLI subcommand, or your real identity provider).

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
    /// Renewed/revoked tokens (wrong `ver`) and unknown subjects (no
    /// [`User`] entry) deliberately map to the same opaque error as
    /// malformed ones, so a caller cannot distinguish "your token was
    /// renewed elsewhere" from "your token was never valid" from "you were
    /// never a user."
    #[error("User is unauthorized!")]
    #[status_code("401")]
    #[code("UNAUTHORIZED")]
    UserUnauthorized,

    /// Token is valid but the authenticated user lacks the role required
    /// for this resource; responds with `403 Forbidden`.
    #[error("Role is forbidden!")]
    #[status_code("403")]
    #[code("FORBIDDEN")]
    RoleForbidden,

    /// The token lifetime configured on [`AuthState`] was zero, or a
    /// `Duration` that truncated to zero seconds. This never reaches a
    /// request: it is a startup-time configuration failure returned by
    /// [`AuthState::new_for_ttl`], and the process should refuse to start.
    ///
    /// The `422` status is carried for completeness — it would apply if
    /// this variant ever surfaced from a handler — but no code path
    /// produces it during a request.
    #[error("Token expiry is invalid!")]
    #[status_code("422")]
    #[code("UNPROCESSABLE_ENTITY")]
    TokenExpiryInvalid,

    /// A user's version counter could not be incremented (it is already
    /// `u64::MAX`); responds with `422 Unprocessable Entity`.
    #[error("Token version is invalid!")]
    #[status_code("422")]
    #[code("UNPROCESSABLE_ENTITY")]
    TokenVersionInvalid,

    /// The system clock is before the Unix epoch, so no token can be
    /// given a sane `exp`. Responds with `500 Internal Server Error`.
    ///
    /// Reaching this means the host's clock is misconfigured, not that the
    /// caller did anything wrong.
    #[error("System clock is invalid!")]
    #[status_code("500")]
    #[code("INTERNAL_SERVER_ERROR")]
    SystemClockInvalid,

    /// The JWT could not be signed. Practically unreachable with HMAC
    /// secrets, but surfaced rather than `panic!`ed so a bad configuration
    /// cannot take down a worker. Responds with `500 Internal Server Error`.
    #[error("Bearer token is not signed! {0}")]
    #[status_code("500")]
    #[code("INTERNAL_SERVER_ERROR")]
    TokenNotSigned(#[from] jsonwebtoken::errors::Error),
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// State captured by the [`authn_layer`] middleware and shared with the
/// lifecycle handlers: the keys used to sign and verify tokens, the
/// validation rules, the user store, and the lifetime assigned to newly
/// minted tokens.
///
/// Built once at startup and passed to
/// [`middleware::from_fn_with_state`](axum::middleware::from_fn_with_state)
/// alongside [`authn_layer`].
#[derive(Clone)]
pub struct AuthState {
    /// Key used to verify a token's signature. Derived once from the
    /// app's JWT secret in [`AuthState::new_for_ttl`].
    decoding_key: DecodingKey,
    /// Key used to sign tokens minted by [`issue_token`] and
    /// [`renew_token`]. Derived from the same secret as `decoding_key`.
    encoding_key: EncodingKey,
    /// Validation rules (algorithm, required claims, clock skew, etc.)
    /// applied to every token. Currently [`Validation::default`].
    validation: Validation,
    /// Store of users: their roles and their current token version, keyed
    /// by the JWT `sub` (user id). Consulted by [`authn_layer`] and
    /// updated by the lifecycle handlers.
    users: UserStore,
    /// Lifetime of tokens minted by this service, in whole seconds.
    ///
    /// Stored truncated to seconds because `exp` is a second-resolution
    /// Unix timestamp; a sub-second remainder would be lost anyway.
    token_ttl: u64,
}

impl AuthState {
    /// Builds authentication state from the app's JWT signing secret and
    /// user store, with the default one-hour token lifetime.
    ///
    /// See [`AuthState::new_for_ttl`] to override the lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::TokenExpiryInvalid`] only if the one-hour
    /// default is invalid, which cannot happen — the `Result` is returned
    /// so callers can `?` it uniformly with [`AuthState::new_for_ttl`].
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use dashmap::DashMap;
    /// use secrecy::SecretString;
    /// use std::sync::Arc;
    ///
    /// let jwt_secret = SecretString::from("super-secret-demo-key".to_string());
    /// let users = Arc::new(DashMap::new());
    ///
    /// let auth_state = auth::AuthState::new(&jwt_secret, users)?;
    /// ```
    pub fn new(jwt_secret: &SecretString, users: UserStore) -> AppResult<Self> {
        Self::new_for_ttl(jwt_secret, users, Duration::from_secs(60 * 60))
    }

    /// Builds authentication state with an explicit token lifetime.
    ///
    /// `jwt_secret` is read via [`ExposeSecret::expose_secret`] only for
    /// the instant it takes to build the keys — the exposed bytes are not
    /// retained; the [`SecretString`] itself is never logged or stored in
    /// plain form by this function.
    ///
    /// Exposed mainly so tests can mint short-lived tokens without
    /// sleeping, and so a deployment that needs a different lifetime can
    /// set one.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::TokenExpiryInvalid`] if `token_ttl` truncates
    /// to zero seconds. A zero lifetime produces a token whose `exp`
    /// equals its mint time, which [`jsonwebtoken::decode`] rejects as
    /// already expired — so the token would be dead on arrival, and a
    /// caller passing a sub-second duration almost certainly meant
    /// something else. Rejecting it here turns a confusing runtime `401`
    /// into a clear configuration failure.
    ///
    /// # Panics
    ///
    /// Does not panic. `DecodingKey::from_secret` /
    /// `EncodingKey::from_secret` accept any byte slice (including an empty
    /// one) and cannot fail.
    pub fn new_for_ttl(
        jwt_secret: &SecretString,
        users: UserStore,
        token_ttl: Duration,
    ) -> AppResult<Self> {
        let secret = jwt_secret.expose_secret().as_bytes();

        // Check the truncated value, not the `Duration` itself: a
        // sub-second duration is not zero, but `as_secs()` on it is.
        let token_ttl = token_ttl.as_secs();
        if token_ttl < 1 {
            return Err(AppError::TokenExpiryInvalid);
        }

        Ok(Self {
            decoding_key: DecodingKey::from_secret(secret),
            encoding_key: EncodingKey::from_secret(secret),
            validation: Validation::default(),
            users,
            token_ttl,
        })
    }
}

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
    /// Roles held by this user, as of the [`UserStore`] lookup performed
    /// by [`authn_layer`] for this request. Not re-checked for the
    /// lifetime of the request, so role changes take effect on the next
    /// request, not the current one.
    pub roles: Vec<String>,
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
/// # struct Claims { sub: String, exp: u64, jti: String, ver: u64 }
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
    /// The token subject — the user id used to look the [`User`] entry up
    /// in the [`UserStore`].
    pub sub: String,
    /// Standard `exp` claim: a Unix timestamp (seconds since the epoch)
    /// after which the token is no longer valid. Enforced by
    /// [`jsonwebtoken::decode`] during [`authn_layer`].
    pub exp: u64,
    /// Standard `jti` claim: a unique identifier for this specific token.
    /// Not used for lookup — carried so tokens are distinguishable in logs
    /// and so a per-token denylist could be added later without a
    /// wire-format change.
    pub jti: String,
    /// This service's revocation generation for `sub`. [`authn_layer`]
    /// rejects the token unless it matches the version currently recorded
    /// in the subject's [`User`] entry.
    pub ver: u64,
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

/// A user: their role assignments and their current token revocation
/// state, together under one key.
///
/// Combining the two means a single lookup resolves both what a user may
/// do and which of their tokens are still valid, and makes it impossible
/// for a user to exist in one store but not the other.
///
/// `active_ver` is the current generation; any token carrying a different
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
pub struct User {
    /// Roles held by this user. Empty means "authenticated but
    /// unauthorized for anything role-gated."
    pub roles: Vec<String>,
    /// The current revocation generation for this user.
    pub active_ver: u64,
    /// The `jti` of the newest token minted for this user, if any.
    pub active_jti: Option<String>,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Convenience alias for results returned by items in [`auth`](self).
pub type AppResult<T> = Result<T, AppError>;

/// In-memory user records, keyed by the JWT `sub` (user id).
///
/// This is a thread-safe, reference-counted, concurrent map, so cloning a
/// `UserStore` is cheap and shares the same underlying data — the same
/// pattern used by [`AppStore`](crate::config::AppStore) for items.
///
/// Each entry holds both the user's roles and their token revocation
/// state, so [`authn_layer`] resolves both with one lookup.
///
/// # Examples
///
/// ```
/// use dashmap::DashMap;
/// use std::sync::Arc;
///
/// let users: Arc<DashMap<String, User>> = Arc::new(DashMap::new());
/// users.insert("alice".to_string(), User { roles: vec!["admin".to_string()], ..Default::default() });
///
/// assert_eq!(
///     users.get("alice").map(|u| u.roles.clone()),
///     Some(vec!["admin".to_string()])
/// );
/// ```
pub type UserStore = Arc<DashMap<String, User>>;

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// Authenticates an incoming request: validates its Bearer token, confirms
/// the token hasn't been renewed or revoked, and, on success, attaches an
/// [`AuthUser`] to the request's extensions before passing it on to `next`.
///
/// Intended to be layered with
/// [`middleware::from_fn_with_state`](axum::middleware::from_fn_with_state)
/// on any (sub-)router that should require authentication; downstream
/// handlers and middleware (such as [`authz_layer`]) can then read the
/// attached [`AuthUser`].
///
/// # Errors
///
/// Returns [`AppError::UserUnauthorized`] if the `Authorization` header is
/// missing, is not a valid UTF-8 string, does not start with `"Bearer "`,
/// if the token fails to decode or validate (bad signature, malformed
/// claims, or an expired `exp`), if the subject has no [`User`] entry, or
/// if the token's `ver` does not match the subject's current version (i.e.
/// it was renewed or revoked).
///
/// # Panics
///
/// Does not panic.
#[tracing::instrument(
    skip_all,
    fields(method = %req.method(), uri = %req.uri()),
    err
)]
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
        .ok_or(AppError::UserUnauthorized)?;

    let Claims { sub: user_id, ver, .. } =
        decode::<Claims>(token, &state.decoding_key, &state.validation)
            .map_err(|_| AppError::UserUnauthorized)?
            .claims;

    // Fail closed: unknown user or stale version => reject. One lookup
    // resolves both the version and the roles.
    let entry = state
        .users
        .get(&user_id)
        .ok_or(AppError::UserUnauthorized)?;

    if ver != entry.active_ver {
        return Err(AppError::UserUnauthorized);
    }

    let roles = entry.roles.clone();
    drop(entry);

    req.extensions_mut().insert(AuthUser { user_id, roles });

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
/// in a closure per call site rather than partially applying it directly.
///
/// # Errors
///
/// Returns [`AppError::RoleForbidden`] if the authenticated user's roles do
/// not include `role`.
///
/// # Panics
///
/// Does not panic.
#[tracing::instrument(
    skip_all,
    fields(role = %role, method = %req.method(), uri = %req.uri()),
    err
)]
pub async fn authz_layer(
    role: &'static str,
    Extension(user): Extension<AuthUser>,
    req: Request,
    next: Next,
) -> AppResult<Response> {
    if user.roles.iter().any(|r| r == role) {
        Ok(next.run(req).await)
    } else {
        Err(AppError::RoleForbidden)
    }
}

/// Computes the `exp` claim for a token minted now, given a lifetime in
/// seconds, as a Unix timestamp.
///
/// Returns [`AppError::SystemClockInvalid`] if the system clock is before
/// the epoch, or [`AppError::TokenExpiryInvalid`] if the addition
/// overflows `u64`.
///
/// Factored out of [`sign_token`] so the `exp` math is a pure function of
/// the clock and a duration, testable without constructing an
/// [`AuthState`].
fn exp_from_ttl(token_ttl: u64) -> AppResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::SystemClockInvalid)?
        .as_secs()
        .checked_add(token_ttl)
        .ok_or(AppError::TokenExpiryInvalid)
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
/// Returns [`AppError::TokenNotSigned`] if the token cannot be signed,
/// or [`AppError::TokenExpiryInvalid`] if the computed `exp` overflows.
///
/// # Panics
///
/// Does not panic.
#[tracing::instrument(skip_all, fields(sub = %user.user_id), err)]
pub async fn issue_token(
    State(state): State<AuthState>,
    Extension(user): Extension<AuthUser>,
) -> AppResult<impl IntoResponse> {
    let mut entry = state
        .users
        .get_mut(&user.user_id)
        .ok_or(AppError::UserUnauthorized)?;

    let ver = entry.active_ver;

    let (token, jti) = sign_token(&user.user_id, state.token_ttl, ver, &state.encoding_key)?;

    entry.active_jti = Some(jti.clone());

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
/// Returns [`AppError::TokenNotSigned`] or
/// [`AppError::TokenExpiryInvalid`] under the same conditions as
/// [`issue_token`], or [`AppError::TokenVersionInvalid`] if the version
/// counter is exhausted.
///
/// # Panics
///
/// Does not panic.
#[tracing::instrument(skip_all, fields(sub = %user.user_id), err)]
pub async fn renew_token(
    State(state): State<AuthState>,
    Extension(user): Extension<AuthUser>,
) -> AppResult<impl IntoResponse> {
    let mut entry = state
        .users
        .get_mut(&user.user_id)
        .ok_or(AppError::UserUnauthorized)?;

    let ver = entry
        .active_ver
        .checked_add(1)
        .ok_or(AppError::TokenVersionInvalid)?;

    let (token, jti) = sign_token(&user.user_id, state.token_ttl, ver, &state.encoding_key)?;

    entry.active_ver = ver;
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
/// Returns [`AppError::UserUnauthorized`] if the caller has no [`User`]
/// entry, or [`AppError::TokenVersionInvalid`] if the version counter is
/// exhausted.
///
/// # Panics
///
/// Does not panic.
#[tracing::instrument(skip_all, fields(sub = %user.user_id), err)]
pub async fn revoke_token(
    State(state): State<AuthState>,
    Extension(user): Extension<AuthUser>,
) -> AppResult<impl IntoResponse> {
    let mut entry = state
        .users
        .get_mut(&user.user_id)
        .ok_or(AppError::UserUnauthorized)?;

    let ver = entry
        .active_ver
        .checked_add(1)
        .ok_or(AppError::TokenVersionInvalid)?;

    let jti = entry.active_jti.take().unwrap_or_default();

    entry.active_ver = ver;

    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            token: None,
            jti,
            ver,
        }),
    ))
}

/// Signs a token for `sub` at the given version, returning the encoded
/// JWT and the `jti` embedded in it.
///
/// Takes the key and lifetime directly rather than `&AuthState` so callers
/// can hold a [`UserStore`] write guard across the call without borrowing
/// the whole state (which would conflict with the guard).
fn sign_token(
    sub: &str,
    token_ttl: u64,
    ver: u64,
    encoding_key: &EncodingKey,
) -> AppResult<(String, String)> {
    let jti = Uuid::new_v4().to_string();

    let claims = Claims {
        sub: sub.to_owned(),
        exp: exp_from_ttl(token_ttl)?,
        jti: jti.clone(),
        ver,
    };

    let token = encode(&Header::default(), &claims, encoding_key)?;

    Ok((token, jti))
}
