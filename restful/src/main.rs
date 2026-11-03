//! HTTP/HTTPS item-management service.
//!
//! This binary starts two servers concurrently:
//! - An HTTP server that redirects all traffic to HTTPS.
//! - An HTTPS (TLS) server that exposes a small CRUD API for [`items::Item`]s
//!   plus a liveliness endpoint.
//!
//! The HTTPS router applies every layer discussed in this service's build-
//! out: CORS ([`cors`]), rate limiting ([`governor`]), hardened response
//! headers ([`xss`]), request/response tracing ([`trace`]), response
//! caching ([`cache`]), CSRF protection ([`csrf`]), and JWT
//! authentication/authorization ([`auth`]).
//!
//! Configuration is read from environment variables (see [`config::AppConfig`])
//! and the process shuts down gracefully on `Ctrl+C`.

/// Program entry point.
///
/// Initializes JSON-formatted tracing (configured via the `RUST_LOG`
/// environment variable, or any other variable understood by
/// [`tracing_subscriber::EnvFilter::from_default_env`]), builds the
/// application state, and runs the app until a `Ctrl+C` signal is received.
///
/// # Errors
///
/// Returns an [`config::AppError`] if application state fails to initialize
/// (e.g. missing environment variables, invalid TLS certificate/key files,
/// invalid rate-limit configuration) or if the process fails to install the
/// `Ctrl+C` signal handler.
#[tokio::main]
async fn main() -> config::AppResult<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("Running {}", env!("CARGO_PKG_NAME"));

    config::run_app(config::AppState::new().await?, tokio::signal::ctrl_c()).await
}
mod auth;
mod xss;

/// CORS policy for this service.
pub mod cors {
    use axum::http::{HeaderValue, Method, header};
    use tower_http::cors::CorsLayer;

    /// Allows the configured frontend origin to call this API, restricted
    /// to the methods/headers this service actually uses. No credentials
    /// mode: auth is via `Authorization: Bearer`, not cookies.
    pub fn cors_layer() -> CorsLayer {
        CorsLayer::new()
            .allow_origin(
                "https://yourapp.example.com"
                    .parse::<HeaderValue>()
                    .expect("valid static origin"),
            )
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
            .allow_credentials(false)
    }
}

/// CSRF protection via [`rune_axum_csrf`].
///
/// A Tower middleware that implements the double-submit cookie pattern:
/// - Safe requests (GET, HEAD, OPTIONS, TRACE) pass through; a fresh
///   `csrf_token` cookie is set if one is absent.
/// - State-changing requests (POST, PUT, PATCH, DELETE) must echo the
///   cookie value in the `x-csrf-token` header. Mismatches are rejected
///   with `403 Forbidden` before the handler runs.
///
/// Unlike `axum_csrf`, no handler extractor is needed — the layer does
/// the verification itself. See [`config::https_router`] for where it's applied.
pub mod csrf {
    use rune_axum_csrf::{/*CsrfConfig, */ CsrfLayer};

    /// Builds the CSRF middleware layer for this service.
    ///
    /// Uses secure defaults: `csrf_token` cookie, `x-csrf-token` header,
    /// 32-byte token, `403 Forbidden` on mismatch.
    ///
    /// In production over HTTPS, consider:
    /// ```ignore
    /// CsrfLayer::new(
    ///     CsrfConfig::new()
    ///         .secure(true)
    ///         .status(StatusCode::FORBIDDEN)
    /// )
    /// ```
    pub fn csrf_layer() -> CsrfLayer {
        CsrfLayer::default()
    }
}

/// Per-peer-IP rate limiting via `governor`/`tower_governor` (GCRA
/// algorithm).
pub mod governor {
    use governor::middleware::NoOpMiddleware;
    use std::{sync::Arc, time::Duration};
    use tower_governor::{
        governor::{GovernorConfig, GovernorConfigBuilder},
        key_extractor::PeerIpKeyExtractor,
    };

    /// This service's rate-limit config type: GCRA, keyed by peer IP.
    pub type GovConfig = GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>;

    /// Convenience alias for results returned by items in [`governor`](self).
    pub type AppResult<T> = Result<T, AppError>;

    /// Errors that can occur while building rate-limit state.
    #[derive(Debug, thiserror::Error)]
    pub enum AppError {
        /// The `per_second`/`burst_size` values were invalid (e.g. zero).
        #[error("Failed to build governor configuration!")]
        FailedConfigGov,
    }

    /// Builds the rate-limit configuration for the given `per_second`
    /// steady-state rate and `burst_size` allowance.
    pub fn new(per_second: u64, burst_size: u32) -> AppResult<Arc<GovConfig>> {
        GovernorConfigBuilder::default()
            .key_extractor(PeerIpKeyExtractor)
            .per_second(per_second)
            .burst_size(burst_size)
            .finish()
            .map(Arc::new)
            .ok_or(AppError::FailedConfigGov)
    }

    /// Builds the rate-limit configuration with this service's defaults:
    /// 2 requests/sec/IP steady state, with bursts up to 20 before
    /// throttling kicks in.
    pub fn default() -> AppResult<Arc<GovConfig>> {
        new(2, 20)
    }

    /// Spawns a background task that purges stale rate-limit buckets from
    /// `config`'s limiter every 60 seconds, so memory doesn't grow
    /// unbounded as distinct peer IPs come and go.
    pub fn spawn_task(config: Arc<GovConfig>) {
        let limiter = config.limiter().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                limiter.retain_recent();
            }
        });
    }
}

/// Request/response tracing — the span-building hook used by
/// `tower_http::trace::TraceLayer`, plus a middleware that logs each
/// request/response's status, headers, and body.
pub mod trace {
    use axum::{
        body::{Body, Bytes},
        extract::Request,
        http::HeaderMap,
        middleware::Next,
        response::Response,
    };
    use http_body_util::BodyExt;
    use serde_json::Value;

    /// Headers whose values are replaced with `"[REDACTED]"` before being
    /// logged, since they carry credentials that must never appear in
    /// logs.
    const REDACTED: &[&str] = &["authorization", "cookie"];

    fn headers_json(headers: &HeaderMap) -> Value {
        headers
            .iter()
            .map(|(name, value)| {
                let v = if REDACTED.contains(&name.as_str().to_ascii_lowercase().as_str()) {
                    "[REDACTED]".to_string()
                } else {
                    value.to_str().unwrap_or("[non-utf8]").to_string()
                };
                (name.to_string(), v)
            })
            .collect()
    }

    fn body_json(bytes: &Bytes) -> Value {
        serde_json::from_slice(bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(bytes).to_string()))
    }

    /// Builds the span `TraceLayer::make_span_with` opens for each
    /// request, carrying a per-request id that every log line inside it —
    /// including `trace_layer`'s — automatically inherits.
    pub fn make_span(req: &axum::http::Request<axum::body::Body>) -> tracing::Span {
        let request_id = uuid::Uuid::new_v4();
        tracing::info_span!(
            "http_request",
            request_id = %request_id,
            method = %req.method(),
            uri = %req.uri(),
        )
    }

    /// Logs method/uri/headers/body on the way in, and status/headers/body
    /// on the way out, as one `tracing::info!` line each.
    pub async fn trace_layer(req: Request, next: Next) -> Response {
        let method = req.method().to_string();
        let uri = req.uri().to_string();
        let req_headers = headers_json(req.headers());

        let (parts, body) = req.into_parts();
        let bytes = body
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();

        tracing::info!(
            method = %method,
            uri = %uri,
            headers = %req_headers,
            body = %body_json(&bytes),
            "request"
        );

        let req = Request::from_parts(parts, Body::from(bytes));
        let res = next.run(req).await;

        let status = res.status().as_u16();
        let res_headers = headers_json(res.headers());
        let (parts, body) = res.into_parts();
        let bytes = body
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();

        tracing::info!(
            status = %status,
            headers = %res_headers,
            body = %body_json(&bytes),
            "response"
        );

        Response::from_parts(parts, Body::from(bytes))
    }
}

/// Application configuration, shared state, and top-level server orchestration.
pub mod config {
    use crate::{
        auth, cache, cors, csrf, governor, handlers,
        items::{self, Item},
        trace, xss,
    };
    use axum::{
        Router,
        extract::FromRef,
        middleware,
        routing::{delete, get, post, put},
    };
    use axum_server::{Handle, tls_rustls::RustlsConfig};
    use dashmap::DashMap;
    use rustls_pki_types::pem::PemObject;
    use secrecy::SecretString;
    use std::{env, future::Future, net::SocketAddr, path::PathBuf, sync::Arc};
    use tokio_util::{sync::CancellationToken, task::TaskTracker};
    use tower_governor::GovernorLayer;
    use uuid::Uuid;

    /// Runs the HTTP and HTTPS servers concurrently until `shutdown_signal`
    /// resolves, then shuts both servers down gracefully.
    #[tracing::instrument(skip_all, err)]
    pub async fn run_app<F>(state: AppState, shutdown_signal: F) -> AppResult<()>
    where
        F: Future<Output = std::io::Result<()>>,
    {
        let http_state = state.clone();
        let https_state = state.clone();

        let config = state.config.clone();
        let http_config = config.clone();
        let https_config = config.clone();

        let token = CancellationToken::new();
        let tracker = TaskTracker::new();

        spawn_server(
            "HTTP",
            move |handle| {
                axum_server::bind(http_config.http_addr)
                    .handle(handle)
                    .serve(
                        http_router(http_state).into_make_service_with_connect_info::<SocketAddr>(),
                    )
            },
            token.child_token(),
            &tracker,
        );

        spawn_server(
            "HTTPS",
            move |handle| {
                axum_server::bind_rustls(
                    https_config.https_addr,
                    (*https_config.tls_config).clone(),
                )
                .handle(handle)
                .serve(
                    https_router(https_state).into_make_service_with_connect_info::<SocketAddr>(),
                )
            },
            token.child_token(),
            &tracker,
        );

        if let Err(err) = shutdown_signal.await {
            token.cancel();
            tracker.close();
            tracker.wait().await;

            return Err(AppError::FailedInitCtrlC(err));
        }

        tracing::info!("[Main] Intercepted shutdown signal! Cancelling child tokens...");
        token.cancel();

        tracker.close();

        tracing::info!("[Main] Waiting until all services gracefully stop...");
        tracker.wait().await;

        tracing::info!("[Main] Stopped all services. Exiting process cleanly...");

        Ok(())
    }

    /// Spawns a named server task on `tracker`, along with a companion task
    /// that triggers a graceful shutdown of that server once `token` is
    /// cancelled.
    pub fn spawn_server<F, B>(
        name: &'static str,
        builder: B,
        token: CancellationToken,
        tracker: &TaskTracker,
    ) where
        B: FnOnce(Handle<SocketAddr>) -> F + Send + 'static,
        F: Future<Output = std::io::Result<()>> + Send + 'static,
    {
        let handle = Handle::new();

        tracker.spawn({
            let handle = handle.clone();

            async move {
                token.cancelled().await;

                tracing::info!("[{name}] Stopping service...");

                handle.graceful_shutdown(None);
            }
        });

        tracker.spawn(async move {
            tracing::info!("[{name}] Starting service...");

            if let Err(err) = builder(handle).await {
                tracing::error!("[{name}] {err}");
            }

            tracing::info!("[{name}] Stopped service.");
        });
    }

    /// Shared application state, cloned into every request handler.
    ///
    /// Cloning is cheap: [`AppConfig`], [`AppStore`], and the other fields
    /// are internally reference-counted, so a clone shares the same
    /// underlying data.
    #[derive(Clone, Debug, FromRef)]
    pub struct AppState {
        /// Static application configuration (addresses, TLS material).
        pub config: AppConfig,
        /// In-memory store of [`Item`]s, keyed by their [`Uuid`].
        pub items: AppStore<Item>,
        /// In-memory store of users: roles and token revocation state,
        /// keyed by user id. Read by [`auth::authn_layer`] and updated by
        /// the token-lifecycle handlers.
        pub users: auth::UserStore,
        /// Response cache read/written by [`cache::cache_layer`], applied
        /// to the read-only item routes in [`https_router`].
        pub cache: cache::CacheState,
        /// Rate-limiter state (GCRA via `governor`), keyed by peer IP.
        pub gvrnr: Arc<governor::GovConfig>,
    }

    impl AppState {
        /// Builds application state by loading [`AppConfig`] from the
        /// environment and initializing empty item and user stores, a
        /// default response cache, and default rate-limit state.
        ///
        /// # Errors
        ///
        /// Propagates any [`AppError`] returned by [`AppConfig::new`], or
        /// [`AppError::FailedConfigGov`] if the rate-limit configuration is
        /// invalid.
        #[tracing::instrument(skip_all, err)]
        pub async fn new() -> AppResult<Self> {
            let config = AppConfig::new().await?;
            let items = Arc::new(DashMap::new());
            let users = Arc::new(DashMap::new());
            let cache = cache::CacheState::default();
            let gvrnr = governor::default()?;

            Ok(Self {
                config,
                items,
                users,
                cache,
                gvrnr,
            })
        }
    }

    /// A thread-safe, reference-counted, concurrent map from [`Uuid`] to
    /// values of type `T`, used as the in-memory backing store for
    /// application resources.
    pub type AppStore<T> = Arc<DashMap<Uuid, T>>;

    /// Builds the plaintext HTTP router.
    ///
    /// This router serves no application routes directly; every request
    /// falls through to [`handlers::redirect_to_https`], which redirects the
    /// client to the equivalent HTTPS URL.
    pub fn http_router(state: AppState) -> Router {
        Router::new()
            .fallback(handlers::redirect_to_https)
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .with_state(state)
    }

    /// Builds the TLS-terminated HTTPS router that serves the item API, the
    /// token-lifecycle endpoints, and a `/healthz` liveliness endpoint, with
    /// every layer applied.
    pub fn https_router(state: AppState) -> Router {
        let items_admin_routes = Router::new()
            .route("/items/{id}", delete(items::delete))
            .layer(middleware::from_fn(|ext, req, next| {
                auth::authz_layer("admin", ext, req, next)
            }));

        // Cache is only layered over the read-only GET routes, so writes on
        // "/items" and "/items/{id}" (registered separately below) are
        // never cached.
        let items_read_routes = Router::new()
            .route("/items", get(items::select))
            .route("/items/{id}", get(items::get))
            .layer(middleware::from_fn_with_state(
                state.cache.clone(),
                cache::cache_layer,
            ));

        // POST/PUT open to any authenticated user; DELETE stays admin-only
        // via `items_admin_routes`.
        let items_write_routes = Router::new()
            .route("/items", post(items::create))
            .route("/items/{id}", put(items::update))
            .merge(items_admin_routes)
            .route("/csrf-token", get(|| async { "ok" })) // priming route for tests
            .layer(csrf::csrf_layer()); // covers POST, PUT, DELETE, and the priming GET

        // Token lifecycle: issue, renew, revoke. All three sit under the
        // `authn_layer` group below, so the caller must already hold a
        // valid bearer token — which is what makes them "self-service".
        // They are not under the CSRF layer: the caller proves intent with
        // a bearer token, not a cookie, so double-submit doesn't apply.
        let token_routes = Router::new().route(
            "/auth/token",
            post(auth::issue_token)
                .put(auth::renew_token)
                .delete(auth::revoke_token),
        );

        let items_routes = Router::new()
            .merge(items_read_routes)
            .merge(items_write_routes)
            .merge(token_routes)
            .layer(middleware::from_fn_with_state(
                auth::AuthState::new(&state.config.jwt_secret, state.users.clone())
                    .expect("one-hour default token TTL is always valid"),
                auth::authn_layer,
            ));

        governor::spawn_task(state.gvrnr.clone());

        Router::new()
            .merge(items_routes)
            .route("/healthz", get(handlers::check_app_liveliness))
            .fallback(handlers::report_route_invalid)
            .layer(
                tower::ServiceBuilder::new()
                    .layer(
                        tower_http::trace::TraceLayer::new_for_http()
                            .make_span_with(trace::make_span)
                            .on_request(())
                            .on_response(()),
                    )
                    .layer(middleware::from_fn(trace::trace_layer))
                    .layer(middleware::from_fn(xss::xss_layer)),
            )
            .layer(GovernorLayer::new(state.gvrnr.clone()))
            .with_state(state)
            .layer(cors::cors_layer()) // outermost: preflight OPTIONS skips everything else
    }

    /// Static configuration for the application, loaded once from the
    /// environment at startup.
    #[derive(Clone, Debug)]
    pub struct AppConfig {
        /// Socket address the plaintext HTTP (redirect) server binds to.
        pub http_addr: SocketAddr,
        /// Socket address the TLS-terminated HTTPS server binds to.
        pub https_addr: SocketAddr,
        /// Filesystem path to the PEM-encoded TLS certificate chain.
        pub cert_path: PathBuf,
        /// Filesystem path to the PEM-encoded TLS private key.
        pub key_path: PathBuf,
        /// Parsed TLS server configuration built from `cert_path` and
        /// `key_path`, shared (via `Arc`) across both server tasks.
        pub tls_config: Arc<RustlsConfig>,
        /// HMAC signing key for JWTs, held as a `SecretString` so it never
        /// appears in `{:?}` output and is zeroized on drop.
        pub jwt_secret: SecretString,
    }

    impl AppConfig {
        /// Loads configuration from environment variables and TLS material
        /// from disk.
        ///
        /// Reads the following environment variables:
        /// - `HTTP_ADDR`: socket address for the HTTP redirect server.
        /// - `HTTPS_ADDR`: socket address for the HTTPS server.
        /// - `CERT_PATH`: path to a PEM file containing one or more
        ///   certificates.
        /// - `KEY_PATH`: path to a PEM file containing a private key.
        /// - `JWT_SECRET`: HMAC signing key used to sign/verify JWTs.
        ///
        /// # Errors
        ///
        /// Returns an [`AppError`] if any of the required environment
        /// variables are unset, addresses don't parse, TLS material can't
        /// be read or combined, or the rate-limit configuration is invalid.
        #[tracing::instrument(skip_all, err)]
        pub async fn new() -> AppResult<Self> {
            let http_addr_raw = env::var("HTTP_ADDR")
                .map_err(|src| AppError::FailedFindEnvVar(src, "HTTP_ADDR".into()))?;
            let http_addr = http_addr_raw
                .parse::<SocketAddr>()
                .map_err(|src| AppError::FailedParseSocketAddr(src, http_addr_raw))?;

            let https_addr_raw = env::var("HTTPS_ADDR")
                .map_err(|src| AppError::FailedFindEnvVar(src, "HTTPS_ADDR".into()))?;
            let https_addr = https_addr_raw
                .parse::<SocketAddr>()
                .map_err(|src| AppError::FailedParseSocketAddr(src, https_addr_raw))?;

            let cert_path_raw = env::var("CERT_PATH")
                .map_err(|src| AppError::FailedFindEnvVar(src, "CERT_PATH".into()))?;
            let cert_path = PathBuf::from(cert_path_raw);

            let cert_pem_file = std::fs::read(&cert_path)
                .map_err(|src| AppError::FailedOpenPublicKeyFile(src, cert_path.clone()))?;
            let certs = rustls_pki_types::CertificateDer::pem_slice_iter(&cert_pem_file)
                .map(|result| {
                    result.map_err(|src| AppError::FailedReadPublicKeyFile(src, cert_path.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if certs.is_empty() {
                return Err(AppError::FailedFindPublicKeys(cert_path.clone()));
            }

            let key_path_raw = env::var("KEY_PATH")
                .map_err(|src| AppError::FailedFindEnvVar(src, "KEY_PATH".into()))?;
            let key_path = PathBuf::from(key_path_raw);

            let key_pem_file = std::fs::read(&key_path)
                .map_err(|src| AppError::FailedOpenPrivateKeyFile(src, key_path.clone()))?;
            let key = rustls_pki_types::PrivateKeyDer::pem_slice_iter(&key_pem_file)
                .next()
                .ok_or_else(|| AppError::FailedFindPrivateKeys(key_path.clone()))?
                .map_err(|src| AppError::FailedReadPrivateKeyFile(src, key_path.clone()))?;

            let tls_config = RustlsConfig::from_der(
                certs.into_iter().map(|cert| cert.to_vec()).collect(),
                key.secret_der().to_vec(),
            )
            .await
            .map_err(|src| AppError::FailedConfigTLS(src, cert_path.clone()))?;

            let tls_config = Arc::new(tls_config);

            let jwt_secret_raw = env::var("JWT_SECRET")
                .map_err(|src| AppError::FailedFindEnvVar(src, "JWT_SECRET".into()))?;
            let jwt_secret = SecretString::from(jwt_secret_raw);

            Ok(Self {
                http_addr,
                https_addr,
                cert_path,
                key_path,
                tls_config,
                jwt_secret,
            })
        }
    }

    /// Convenience alias for results returned by functions in [`config`](self).
    pub type AppResult<T> = Result<T, AppError>;

    /// Errors that can occur while loading configuration or running the
    /// application's top-level lifecycle.
    #[derive(Debug, thiserror::Error)]
    pub enum AppError {
        /// A required environment variable (named by the second field) was
        /// not set.
        #[error("Failed to find environment variable {1}! {0}")]
        FailedFindEnvVar(#[source] std::env::VarError, String),

        /// The value of an environment variable could not be parsed as a
        /// [`std::net::SocketAddr`].
        #[error("Failed to parse socket address {1}! {0}")]
        FailedParseSocketAddr(#[source] std::net::AddrParseError, String),

        /// The TLS certificate file at the given path could not be opened.
        #[error("Failed to open public key file {1}! {0}")]
        FailedOpenPublicKeyFile(#[source] std::io::Error, PathBuf),

        /// The TLS certificate file at the given path could not be parsed
        /// as PEM.
        #[error("Failed to read public key file {1}! {0}")]
        FailedReadPublicKeyFile(#[source] rustls_pki_types::pem::Error, PathBuf),

        /// The TLS certificate file at the given path contained no
        /// certificates.
        #[error("Failed to find public keys in PEM file {0}!")]
        FailedFindPublicKeys(PathBuf),

        /// The TLS private key file at the given path could not be opened.
        #[error("Failed to open private key file {1}! {0}")]
        FailedOpenPrivateKeyFile(#[source] std::io::Error, PathBuf),

        /// The TLS private key file at the given path could not be parsed
        /// as PEM.
        #[error("Failed to read private key file {1}! {0}")]
        FailedReadPrivateKeyFile(#[source] rustls_pki_types::pem::Error, PathBuf),

        /// The TLS private key file at the given path contained no private
        /// keys.
        #[error("Failed to find private keys in PEM file {0}!")]
        FailedFindPrivateKeys(PathBuf),

        /// The certificate and key at the given path could not be combined
        /// into a valid [`RustlsConfig`].
        #[error("Failed to configure TLS from file {1}! {0}")]
        FailedConfigTLS(#[source] std::io::Error, PathBuf),

        /// The rate-limit configuration was invalid.
        #[error("Failed to configure rate limiter! {0}")]
        FailedConfigGov(#[from] crate::governor::AppError),

        /// The `Ctrl+C` signal handler failed to install or await.
        #[error("Failed to initialize Ctrl+C interceptor! {0}")]
        FailedInitCtrlC(#[source] std::io::Error),
    }
}

/// Top-level HTTP request handlers not specific to any single resource.
pub mod handlers {
    use crate::config::AppState;
    use axum::{
        Json,
        extract::State,
        http::{
            HeaderValue, StatusCode, Uri,
            header::{InvalidHeaderValue, LOCATION},
        },
        response::IntoResponse,
    };
    use serde_json::json;

    /// Redirects any request received on the plaintext HTTP server to the
    /// equivalent path on the HTTPS server, using an HTTP `307 Temporary
    /// Redirect`.
    #[tracing::instrument(skip_all, err)]
    pub async fn redirect_to_https(
        State(state): State<AppState>,
        uri: Uri,
    ) -> AppResult<impl IntoResponse> {
        let addr = &state.config.https_addr;

        let path_query = uri.path_and_query().map_or("/", |pq| pq.as_str());

        let redirect_url = format!("https://{addr}{path_query}");

        let location =
            HeaderValue::try_from(redirect_url.clone()).map_err(AppError::FailedCreateHeader)?;

        Ok((
            StatusCode::TEMPORARY_REDIRECT,
            [(LOCATION, location)],
            Json(json!({"status": format!("Temporarily redirecting to {redirect_url}.")})),
        ))
    }

    /// Liveliness probe handler, mounted at `GET /healthz`.
    #[tracing::instrument(skip_all, err)]
    pub async fn check_app_liveliness() -> AppResult<impl IntoResponse> {
        Ok((StatusCode::OK, Json(json!({"status": "App is lively."}))))
    }

    /// Fallback handler for the HTTPS router, invoked when a request does
    /// not match any registered route.
    #[tracing::instrument(skip_all, err)]
    pub async fn report_route_invalid(uri: Uri) -> AppResult<impl IntoResponse> {
        let path = uri.path();
        Ok((
            StatusCode::NOT_FOUND,
            Json(json!({"status": format!("Invalid route {path}.")})),
        ))
    }

    /// Convenience alias for results returned by handlers in
    /// [`handlers`](self).
    type AppResult<T> = Result<T, AppError>;

    /// Errors that can occur in top-level request handlers.
    #[derive(Debug, thiserror::Error, axum_error_handler::AxumErrorResponse)]
    pub enum AppError {
        /// The redirect target URL could not be encoded as an HTTP header
        /// value; responds with `400 Bad Request`.
        #[error("Failed to create header! {0}")]
        #[status_code("400")]
        FailedCreateHeader(InvalidHeaderValue),
    }
}

/// CRUD API for `\[`Item`\]` resources, backed by an in-memory
/// [`AppStore`](crate::config::AppStore).
pub mod items {
    use crate::config::AppStore;
    use axum::{
        extract::{Json, Path, Query, State},
        http::StatusCode,
        response::IntoResponse,
    };
    use axum_valid::Valid;
    use uuid::Uuid;

    /// Handles `POST /items`: creates a new [`Item`].
    #[tracing::instrument(skip_all, err)]
    pub async fn create(
        State(state): State<AppStore<Item>>,
        Valid(Json(payload)): Valid<Json<CreateJsonPayload>>,
    ) -> AppResult<impl IntoResponse> {
        let id = uuid::Uuid::new_v4();

        let item: Item = payload.into();

        let item_response = ItemResponse {
            id,
            item: item.clone(),
        };

        state.insert(id, item);

        Ok((StatusCode::CREATED, Json(item_response)))
    }

    /// Request body for [`create`].
    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct CreateJsonPayload {
        /// The new item's name. Must be non-empty.
        #[validate(length(min = 1, message = "field in create json payload is missing!"))]
        name: String,
        /// The new item's description. Must be non-empty.
        #[validate(length(min = 1, message = "field in create json payload is missing!"))]
        desc: String,
    }

    impl From<CreateJsonPayload> for Item {
        /// Converts a validated create payload directly into an [`Item`].
        fn from(payload: CreateJsonPayload) -> Self {
            Self {
                name: payload.name,
                desc: payload.desc,
            }
        }
    }

    /// A named item resource stored by this service.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Item {
        /// The item's name.
        pub name: String,
        /// The item's description.
        pub desc: String,
    }

    impl Item {
        /// Applies a partial update to this item in place.
        fn edit(&mut self, payload: UpdateJsonPayload) {
            if let Some(name) = payload.name {
                self.name = name;
            }
            if let Some(desc) = payload.desc {
                self.desc = desc;
            }
        }
    }

    /// JSON response envelope pairing an [`Item`] with its [`Uuid`].
    #[derive(Debug, serde::Serialize)]
    struct ItemResponse {
        /// The item's unique identifier.
        id: Uuid,
        /// The item itself.
        item: Item,
    }

    /// Handles `DELETE /items/{id}`: removes and returns the item.
    #[tracing::instrument(skip_all, err)]
    pub async fn delete(
        State(state): State<AppStore<Item>>,
        Path(GetPathId { id }): Path<GetPathId>,
    ) -> AppResult<impl IntoResponse> {
        let (_, item) = state
            .remove(&id)
            .ok_or_else(|| AppError::NotFound(id.to_string()))?;

        let item_response = ItemResponse {
            id,
            item: item.clone(),
        };

        Ok((StatusCode::OK, Json(item_response)))
    }

    /// Path parameters shared by the single-item routes.
    #[derive(Debug, serde::Deserialize)]
    pub struct GetPathId {
        /// The requested item's unique identifier.
        id: Uuid,
    }

    /// Handles `GET /items/{id}`: fetches a single item by id.
    #[tracing::instrument(skip_all, err)]
    pub async fn get(
        State(state): State<AppStore<Item>>,
        Path(GetPathId { id }): Path<GetPathId>,
    ) -> AppResult<impl IntoResponse> {
        let item = state
            .get(&id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| AppError::NotFound(id.to_string()))?;

        let item_response = ItemResponse { id, item };

        Ok((StatusCode::OK, Json(item_response)))
    }

    /// Handles `GET /items`: lists items, optionally filtered.
    #[tracing::instrument(skip_all, err)]
    pub async fn select(
        State(state): State<AppStore<Item>>,
        Valid(Query(params)): Valid<Query<SelectQueryParams>>,
    ) -> AppResult<impl IntoResponse> {
        let results: Vec<ItemResponse> = state
            .iter()
            .filter_map(|entry| {
                let item = entry.value();

                if let Some(ref filter_name) = params.name
                    && !item.name.contains(filter_name)
                {
                    return None;
                }

                if let Some(ref filter_desc) = params.desc
                    && !item.desc.contains(filter_desc)
                {
                    return None;
                }

                Some(ItemResponse {
                    id: *entry.key(),
                    item: (*item).clone(),
                })
            })
            .collect();

        Ok((StatusCode::OK, Json(results)))
    }

    /// Query parameters accepted by [`select`].
    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct SelectQueryParams {
        /// Optional substring filter applied to each item's `name`.
        #[validate(length(min = 1, message = "field in select query params is missing!"))]
        name: Option<String>,
        /// Optional substring filter applied to each item's `desc`.
        #[validate(length(min = 1, message = "field in select query params is missing!"))]
        desc: Option<String>,
    }

    /// Handles `PUT /items/{id}`: applies a partial update.
    #[tracing::instrument(skip_all, err)]
    pub async fn update(
        State(state): State<AppStore<Item>>,
        Path(GetPathId { id }): Path<GetPathId>,
        Valid(Json(payload)): Valid<Json<UpdateJsonPayload>>,
    ) -> AppResult<impl IntoResponse> {
        let mut item = state
            .get_mut(&id)
            .ok_or_else(|| AppError::NotFound(id.to_string()))?;

        item.edit(payload);

        let item_response = ItemResponse {
            id,
            item: item.clone(),
        };

        Ok((StatusCode::OK, Json(item_response)))
    }

    /// Request body for [`update`]. Every field is optional.
    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct UpdateJsonPayload {
        /// New name for the item. If present, must be non-empty.
        #[validate(length(min = 1, message = "field in update json payload is missing!"))]
        name: Option<String>,
        /// New description for the item. If present, must be non-empty.
        #[validate(length(min = 1, message = "field in update json payload is missing!"))]
        desc: Option<String>,
    }

    /// Convenience alias for results returned by handlers in
    /// [`items`](self).
    pub type AppResult<T> = Result<T, AppError>;

    /// Errors that can occur while handling item API requests.
    #[derive(Debug, thiserror::Error, axum_error_handler::AxumErrorResponse)]
    pub enum AppError {
        /// The request body or query parameters failed validation;
        /// responds with `422 Unprocessable Entity`.
        #[error("Failed to validate request! {0}")]
        #[status_code("422")]
        #[code("UNPROCESSABLE_ENTITY")]
        UnprocessableEntity(#[from] validator::ValidationErrors),

        /// No item exists with the requested id;
        /// responds with `404 Not Found`.
        #[error("Failed to find {0} id in request path!")]
        #[status_code("404")]
        #[code("NOT_FOUND")]
        NotFound(String),
    }
}

/// A response cache for idempotent, read-only routes, implemented as an
/// ordinary `axum::middleware::from_fn` handler backed by a [`moka`] cache.
pub mod cache {
    use axum::{
        body::{Body, Bytes},
        extract::{Request, State},
        http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
        middleware::Next,
        response::Response,
    };
    use http_body_util::BodyExt;
    use moka::future::Cache;
    use std::time::Duration;

    /// Suggested `max_capacity` (entry count) for [`CacheState::new`].
    pub const DEFAULT_MAX_CAPACITY: u64 = 10_000;

    /// Suggested `time_to_live` for [`CacheState::new`].
    pub const DEFAULT_TIME_TO_LIVE: Duration = Duration::from_secs(30);

    /// Response header set on every response returned by [`cache_layer`],
    /// reporting whether it was served from the cache (`"HIT"`) or freshly
    /// computed (`"MISS"`).
    const CACHE_STATUS_HEADER: HeaderName = HeaderName::from_static("x-cache");

    /// Shared response cache state, cloned into every request that passes
    /// through [`cache_layer`].
    #[derive(Clone, Debug)]
    pub struct CacheState {
        /// Cached responses, keyed by path + sorted query parameters.
        cache: Cache<String, CachedResponse>,
    }

    impl CacheState {
        /// Builds an empty response cache with the given `max_capacity`
        /// (entry count) and `time_to_live`.
        pub fn new(max_capacity: u64, time_to_live: Duration) -> Self {
            Self {
                cache: Cache::builder()
                    .max_capacity(max_capacity)
                    .time_to_live(time_to_live)
                    .build(),
            }
        }
    }

    impl Default for CacheState {
        /// Builds an empty response cache using this service's defaults.
        fn default() -> Self {
            Self::new(DEFAULT_MAX_CAPACITY, DEFAULT_TIME_TO_LIVE)
        }
    }

    /// The parts of a [`Response`] needed to reconstruct it later.
    #[derive(Clone, Debug)]
    struct CachedResponse {
        /// The original response's status code.
        status: StatusCode,
        /// The original response's headers.
        headers: HeaderMap,
        /// The original response's body, fully buffered.
        body: Bytes,
    }

    /// Builds the cache key for `uri`: its path, plus its query parameters
    /// (if any) sorted so that two requests differing only in parameter
    /// order land on the same cache entry.
    fn cache_key(uri: &Uri) -> String {
        let Some(query) = uri.query() else {
            return uri.path().to_string();
        };

        let mut params: Vec<&str> = query.split('&').collect();
        params.sort_unstable();

        format!("{}?{}", uri.path(), params.join("&"))
    }

    /// Caches `GET` responses by [`cache_key`] and serves repeat requests
    /// straight from the cache.
    pub async fn cache_layer(
        State(state): State<CacheState>,
        req: Request,
        next: Next,
    ) -> Response {
        if req.method() != Method::GET {
            return next.run(req).await;
        }

        let key = cache_key(req.uri());

        if let Some(cached) = state.cache.get(&key).await {
            let mut response = Response::builder()
                .status(cached.status)
                .body(Body::from(cached.body.clone()))
                .expect("rebuilding a response from previously valid parts cannot fail");
            *response.headers_mut() = cached.headers.clone();
            response
                .headers_mut()
                .insert(CACHE_STATUS_HEADER, HeaderValue::from_static("HIT"));

            return response;
        }

        let response = next.run(req).await;
        let (parts, body) = response.into_parts();

        let bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => Bytes::new(),
        };

        state
            .cache
            .insert(
                key,
                CachedResponse {
                    status: parts.status,
                    headers: parts.headers.clone(),
                    body: bytes.clone(),
                },
            )
            .await;

        let mut response = Response::from_parts(parts, Body::from(bytes));
        response
            .headers_mut()
            .insert(CACHE_STATUS_HEADER, HeaderValue::from_static("MISS"));

        response
    }
}
