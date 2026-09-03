//! HTTP/HTTPS item-management service.
//!
//! This binary starts two servers concurrently:
//! - An HTTP server that redirects all traffic to HTTPS.
//! - An HTTPS (TLS) server that exposes a small CRUD API for [`items::Item`]s
//!   plus a liveliness endpoint.
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
/// (e.g. missing environment variables, invalid TLS certificate/key files)
/// or if the process fails to install the `Ctrl+C` signal handler.
#[tokio::main]
async fn main() -> config::AppResult<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    tracing::info!("Running {}", env!("CARGO_PKG_NAME"));

    config::run_app(config::AppState::new().await?, tokio::signal::ctrl_c()).await
}

/// Application configuration, shared state, and top-level server orchestration.
pub mod config {
    use crate::{
        auth, cache, handlers,
        items::{self, Item},
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
    use uuid::Uuid;

    /// Runs the HTTP and HTTPS servers concurrently until `shutdown_signal`
    /// resolves, then shuts both servers down gracefully.
    ///
    /// The HTTP server only ever redirects requests to the HTTPS server; all
    /// application routes are served over HTTPS. Both servers are spawned as
    /// tracked, cancellable tasks so that a shutdown signal (or a failure to
    /// install one) cleanly stops both before this function returns.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::FailedInitCtrlC`] if `shutdown_signal` itself
    /// resolves to an `Err`, which indicates the shutdown signal could not be
    /// awaited (e.g. the OS failed to deliver signal notifications). In that
    /// case both servers are cancelled and awaited before the error is
    /// returned. Individual server errors (e.g. failure to bind a socket) are
    /// logged rather than propagated, so that a fault in one server does not
    /// prevent the other from running.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use tokio::signal;
    ///
    /// let state = config::AppState::new().await?;
    /// config::run_app(state, signal::ctrl_c()).await?;
    /// ```
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
                    .serve(http_router(http_state).into_make_service())
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
                .serve(https_router(https_state).into_make_service())
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
    ///
    /// `builder` receives an [`axum_server::Handle`] and must return the
    /// future that actually runs the server (e.g. the result of calling
    /// `.serve(...)` on an `axum_server` builder). Any error returned by that
    /// future is logged with the given `name` and does not panic the task.
    ///
    /// # Panics
    ///
    /// Does not panic itself; however, if `builder` or the returned future
    /// panics, that panic will propagate to and abort the spawned task (it
    /// will not unwind into the caller of `spawn_server`).
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
    /// Cloning is cheap: [`AppConfig`] and [`AppStore`] are internally
    /// reference-counted, so a clone shares the same underlying data.
    #[derive(Clone, Debug, FromRef)]
    pub struct AppState {
        /// Static application configuration (addresses, TLS material).
        pub config: AppConfig,
        /// In-memory store of [`Item`]s, keyed by their [`Uuid`].
        pub items: AppStore<Item>,
        /// In-memory RBAC store: user id -> roles, read by
        /// [`auth::authenticate`].
        pub roles: auth::RoleStore,
        /// Response cache read/written by [`cache::cache_response`],
        /// applied to the read-only item routes in [`https_router`].
        pub cache: cache::CacheState,
    }

    impl AppState {
        /// Builds application state by loading [`AppConfig`] from the
        /// environment and initializing empty item and role stores.
        ///
        /// # Errors
        ///
        /// Propagates any [`AppError`] returned by [`AppConfig::new`].
        #[tracing::instrument(skip_all, err)]
        pub async fn new() -> AppResult<Self> {
            let config = AppConfig::new().await?;
            let items = Arc::new(DashMap::new());
            let roles = Arc::new(DashMap::new());
            let cache = cache::CacheState::new();
            Ok(Self {
                config,
                items,
                roles,
                cache,
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

    /// Builds the TLS-terminated HTTPS router that serves the item API and a
    /// `/healthz` liveliness endpoint.
    ///
    /// The item routes are authenticated via [`auth::authenticate`]; `DELETE
    /// /items/{id}` additionally requires the `"admin"` role via
    /// [`auth::authorize`]. `GET /items` and `GET /items/{id}` are served
    /// through [`cache::cache_response`], so a repeat read is answered
    /// straight from the cache instead of the store; `POST`/`PUT`/`DELETE`
    /// are never cached. `/healthz` and the fallback are unauthenticated.
    ///
    /// Requests that don't match any known route fall through to
    /// [`handlers::report_route_invalid`].
    pub fn https_router(state: AppState) -> Router {
        let admin_only = Router::new()
            .route("/items/{id}", delete(items::delete))
            .layer(middleware::from_fn(|ext, req, next| {
                auth::authorize("admin", ext, req, next)
            }));

        // Cache is only layered over the read-only GET routes, so writes on
        // "/items" and "/items/{id}" (registered separately below) are
        // never cached.
        let items_read_routes = Router::new()
            .route("/items", get(items::select))
            .route("/items/{id}", get(items::get))
            .layer(middleware::from_fn_with_state(
                state.cache.clone(),
                cache::cache_response,
            ));

        let items_write_routes = Router::new()
            .route("/items", post(items::create))
            .route("/items/{id}", put(items::update));

        let items_routes = Router::new()
            .merge(items_read_routes)
            .merge(items_write_routes)
            .merge(admin_only)
            .layer(middleware::from_fn_with_state(
                auth::AuthState::new(&state.config.jwt_secret, state.roles.clone()),
                auth::authenticate,
            ));

        Router::new()
            .merge(items_routes)
            .route("/healthz", get(handlers::check_app_liveliness))
            .fallback(handlers::report_route_invalid)
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .with_state(state)
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
        /// Returns an [`AppError`] if:
        /// - any of the required environment variables are unset
        ///   ([`AppError::FailedFindEnvVar`]);
        /// - `HTTP_ADDR` or `HTTPS_ADDR` cannot be parsed as a
        ///   [`SocketAddr`] ([`AppError::FailedParseSocketAddr`]);
        /// - the certificate or key file cannot be opened
        ///   ([`AppError::FailedOpenPublicKeyFile`],
        ///   [`AppError::FailedOpenPrivateKeyFile`]);
        /// - the certificate or key file cannot be parsed as PEM
        ///   ([`AppError::FailedReadPublicKeyFile`],
        ///   [`AppError::FailedReadPrivateKeyFile`]);
        /// - the certificate or key file contains no usable entries
        ///   ([`AppError::FailedFindPublicKeys`],
        ///   [`AppError::FailedFindPrivateKeys`]);
        /// - the certificate and key cannot be combined into a valid TLS
        ///   configuration ([`AppError::FailedConfigTLS`]).
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
    ///
    /// The redirect target is built from [`AppConfig::https_addr`] combined
    /// with the incoming request's path and query string.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::FailedCreateHeader`] if the computed redirect URL
    /// is not a valid HTTP header value (e.g. it contains characters that
    /// cannot appear in a `Location` header).
    ///
    /// [`AppConfig::https_addr`]: crate::config::AppConfig::https_addr
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
    ///
    /// Always succeeds; its purpose is simply to confirm that the HTTPS
    /// server is up and responding to requests.
    #[tracing::instrument(skip_all, err)]
    pub async fn check_app_liveliness() -> AppResult<impl IntoResponse> {
        Ok((StatusCode::OK, Json(json!({"status": "App is lively."}))))
    }

    /// Fallback handler for the HTTPS router, invoked when a request does
    /// not match any registered route.
    ///
    /// Always responds with `404 Not Found` and a JSON body describing the
    /// invalid path.
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

    /// Handles `POST /items`: creates a new [`Item`] from the request body
    /// and inserts it into the store under a freshly generated [`Uuid`].
    ///
    /// # Errors
    ///
    /// Returns [`AppError::UnprocessableEntity`] if the JSON body fails
    /// validation (e.g. an empty `name` or `desc`).
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
        ///
        /// Only fields present (`Some`) in `payload` are overwritten; `None`
        /// fields leave the corresponding value unchanged.
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

    /// Handles `DELETE /items/{id}`: removes and returns the item with the
    /// given id.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] if no item exists with the given id.
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

    /// Path parameters shared by the single-item routes
    /// (`GET`/`PUT`/`DELETE /items/{id}`).
    #[derive(Debug, serde::Deserialize)]
    pub struct GetPathId {
        /// The requested item's unique identifier.
        id: Uuid,
    }

    /// Handles `GET /items/{id}`: fetches a single item by id.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] if no item exists with the given id.
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

    /// Handles `GET /items`: lists items, optionally filtered by substring
    /// match on `name` and/or `desc`.
    ///
    /// When both `name` and `desc` filters are supplied, an item must match
    /// both to be included in the results.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::UnprocessableEntity`] if a supplied filter
    /// parameter is present but empty.
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
        /// Optional substring filter applied to each item's `name`. If
        /// present, must be non-empty.
        #[validate(length(min = 1, message = "field in select query params is missing!"))]
        name: Option<String>,
        /// Optional substring filter applied to each item's `desc`. If
        /// present, must be non-empty.
        #[validate(length(min = 1, message = "field in select query params is missing!"))]
        desc: Option<String>,
    }

    /// Handles `PUT /items/{id}`: applies a partial update to an existing
    /// item.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] if no item exists with the given id,
    /// or [`AppError::UnprocessableEntity`] if the JSON body fails
    /// validation.
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

    /// Request body for [`update`]. Every field is optional; only supplied
    /// fields are changed.
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

        /// No item exists with the requested id (given as a string);
        /// responds with `404 Not Found`.
        #[error("Failed to find {0} id in request path!")]
        #[status_code("404")]
        #[code("NOT_FOUND")]
        NotFound(String),
    }
}

/// A response cache for idempotent, read-only routes, implemented as an
/// ordinary `axum::middleware::from_fn` handler backed by a [`moka`] cache.
///
/// [`cache_response`] is the middleware itself: layered onto a router (or
/// sub-router), it caches the full [`Response`] for every `GET` request by
/// path + sorted query parameters, and serves that cached response directly
/// on a repeat request instead of re-invoking the handler. Non-`GET`
/// requests (which this service's API only uses for mutations) always fall
/// straight through to the handler and are never cached, so a stale write
/// is never possible. Every response — hit or miss — carries an `x-cache`
/// header set to `"HIT"` or `"MISS"`, so callers can tell which happened.
///
/// The cache itself lives in [`CacheState`], which — like
/// [`AppStore`](crate::config::AppStore) and
/// [`RoleStore`](crate::auth::RoleStore) — is internally reference-counted
/// and internally concurrent, so cloning it is cheap and requires no
/// `Mutex`/`RwLock` of its own.
///
/// # Examples
///
/// Applying it to a sub-router of only the routes that should be cached,
/// the same way [`auth::authenticate`](crate::auth::authenticate) is
/// layered with its own state:
///
/// ```ignore
/// use axum::{middleware, routing::get, Router};
///
/// let items_read_routes = Router::new()
///     .route("/items", get(items::select))
///     .route("/items/{id}", get(items::get))
///     .layer(middleware::from_fn_with_state(
///         cache_state.clone(),
///         cache::cache_response,
///     ));
/// ```
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

    /// Response header set on every response returned by [`cache_response`],
    /// reporting whether it was served from the cache (`"HIT"`) or freshly
    /// computed (`"MISS"`).
    const CACHE_STATUS_HEADER: HeaderName = HeaderName::from_static("x-cache");

    /// Shared response cache state, cloned into every request that passes
    /// through [`cache_response`].
    ///
    /// Cloning is cheap: the underlying [`moka::future::Cache`] is itself
    /// reference-counted and internally sharded/concurrent.
    #[derive(Clone, Debug)]
    pub struct CacheState {
        /// Cached responses, keyed by path + sorted query parameters (see
        /// [`cache_key`]).
        cache: Cache<String, CachedResponse>,
    }

    impl Default for CacheState {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CacheState {
        /// Builds an empty response cache with the given `max_capacity`
        /// (entry count) and `time_to_live`.
        ///
        /// # Examples
        ///
        /// ```ignore
        /// let state = cache::CacheState::new();
        /// ```
        pub fn new() -> Self {
            Self {
                cache: Cache::builder()
                    .max_capacity(10_000)
                    .time_to_live(Duration::from_secs(30))
                    .build(),
            }
        }
    }

    /// The parts of a [`Response`] needed to reconstruct it later; stored
    /// in [`CacheState`] instead of the `Response` itself, since a
    /// `Response`'s body is a one-shot stream and can't be cloned or
    /// stored directly.
    #[derive(Clone, Debug)]
    struct CachedResponse {
        /// The original response's status code.
        status: StatusCode,
        /// The original response's headers, replayed as-is on a hit (the
        /// `x-cache` header is overwritten separately on every reply).
        headers: HeaderMap,
        /// The original response's body, fully buffered.
        body: Bytes,
    }

    /// Builds the cache key for `uri`: its path, plus its query parameters
    /// (if any) sorted so that two requests differing only in parameter
    /// order land on the same cache entry. The method is not part of the
    /// key, since [`cache_response`] only ever caches `GET` requests.
    fn cache_key(uri: &Uri) -> String {
        let Some(query) = uri.query() else {
            return uri.path().to_string();
        };

        let mut params: Vec<&str> = query.split('&').collect();
        params.sort_unstable();

        format!("{}?{}", uri.path(), params.join("&")).to_string()
    }

    /// Caches `GET` responses by [`cache_key`] and serves repeat requests
    /// straight from the cache, bypassing `next` (and therefore the
    /// handler and everything after this middleware) entirely on a hit.
    /// Every response leaving this middleware carries an `x-cache: HIT` or
    /// `x-cache: MISS` header reporting what happened.
    ///
    /// Any request whose method is not `GET` is passed straight to `next`
    /// without consulting or populating the cache, since this service only
    /// uses other methods for mutations that must never be served stale.
    ///
    /// On a `GET` miss, the response returned by `next` is buffered in
    /// full so it can be stored in the cache, then re-emitted as a fresh
    /// `Response` built from those same buffered bytes (a `Response`'s
    /// body can't be read twice, so the original can't be reused directly
    /// after buffering it).
    ///
    /// Intended to be layered with
    /// [`middleware::from_fn_with_state`](axum::middleware::from_fn_with_state)
    /// (not plain `from_fn`, which fixes its state to `()` and can't
    /// satisfy this handler's `State<CacheState>` extractor) on any
    /// (sub-)router whose `GET` routes are safe to cache — see the
    /// [module-level example](self#examples).
    ///
    /// # Panics
    ///
    /// Does not panic: rebuilding a [`Response`] from a previously valid
    /// status/header/body triple cannot fail.
    pub async fn cache_response(
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

        // Buffer the body so it can both be cached and still returned.
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

/// JWT authentication and role-based authorization for this service,
/// implemented as ordinary `axum::middleware::from_fn`/`from_fn_with_state`
/// handlers.
///
/// Two middleware functions do the work:
/// - [`authenticate`] verifies the `Authorization: Bearer <jwt>` header,
///   decodes [`Claims`], looks the subject up in an in-memory [`RoleStore`],
///   and inserts an [`AuthUser`] into the request's extensions.
/// - [`authorize`] reads that [`AuthUser`] back out and rejects the request
///   if it doesn't hold the required role. It must run *after*
///   [`authenticate`] on the same request, since it only reads what that
///   middleware wrote.
///
/// # Examples
///
/// Applying both to a sub-router (see [`AuthState::new`] and [`authorize`]
/// for the pieces used here):
///
/// ```ignore
/// use axum::{middleware, routing::delete, Router};
///
/// let admin_only = Router::new()
///     .route("/items/{id}", delete(items::delete))
///     .layer(middleware::from_fn(|ext, req, next| {
///         auth::authorize("admin", ext, req, next)
///     }));
///
/// let protected = Router::new()
///     .merge(admin_only)
///     .layer(middleware::from_fn_with_state(
///         auth::AuthState::new(&jwt_secret, roles.clone()),
///         auth::authenticate,
///     ));
/// ```
pub mod auth {
    use axum::{
        Extension,
        extract::{Request, State},
        http::header,
        middleware::Next,
        response::Response,
    };
    use dashmap::DashMap;
    use jsonwebtoken::{DecodingKey, Validation, decode};
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

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

    /// JWT claims this service expects to find in a validated Bearer token.
    ///
    /// Decoded by [`authenticate`] via [`jsonwebtoken::decode`], which also
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
        /// [`jsonwebtoken::decode`] during [`authenticate`].
        pub exp: usize,
    }

    /// The authenticated identity attached to a request's extensions by
    /// [`authenticate`].
    ///
    /// Handlers can read it back out via `Extension<AuthUser>`, and
    /// [`authorize`] reads it to perform its role check.
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
        /// performed by [`authenticate`] for this request. Not re-checked
        /// for the lifetime of the request, so role changes take effect on
        /// the next request, not the current one.
        pub roles: Vec<String>,
    }

    /// State captured by the [`authenticate`] middleware: the key/rules
    /// used to validate incoming tokens, and the store used to resolve
    /// roles for the validated subject.
    ///
    /// Built once at startup and passed to
    /// [`middleware::from_fn_with_state`](axum::middleware::from_fn_with_state)
    /// alongside [`authenticate`].
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

    /// Authenticates an incoming request: validates its Bearer token and,
    /// on success, attaches an [`AuthUser`] to the request's extensions
    /// before passing it on to `next`.
    ///
    /// Intended to be layered with
    /// [`middleware::from_fn_with_state`](axum::middleware::from_fn_with_state)
    /// on any (sub-)router that should require authentication; downstream
    /// handlers and middleware (such as [`authorize`]) can then read the
    /// attached [`AuthUser`].
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use axum::{middleware, Router};
    ///
    /// let protected = Router::new()
    ///     // ...routes...
    ///     .layer(middleware::from_fn_with_state(auth_state, auth::authenticate));
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
    pub async fn authenticate(
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

    /// Rejects a request unless the [`AuthUser`] attached by
    /// [`authenticate`] holds `role`.
    ///
    /// Must run *after* [`authenticate`] on the same request — it only
    /// reads the [`AuthUser`] that middleware wrote, and does not itself
    /// validate the token.
    ///
    /// Because [`middleware::from_fn`](axum::middleware::from_fn) expects a
    /// fixed function signature, `role` is supplied by wrapping this
    /// function in a closure per call site rather than partially applying
    /// it directly (see the module-level example).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use axum::{middleware, routing::delete, Router};
    ///
    /// let admin_only = Router::new()
    ///     .route("/items/{id}", delete(items::delete))
    ///     .layer(middleware::from_fn(|ext, req, next| {
    ///         auth::authorize("admin", ext, req, next)
    ///     }));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Forbidden`] if the authenticated user's roles do
    /// not include `role`.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub async fn authorize(
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

    /// Convenience alias for results returned by items in [`auth`](self).
    pub type AppResult<T> = Result<T, AppError>;

    /// Errors produced while authenticating or authorizing a request.
    ///
    /// Implements [`IntoResponse`] (via `#[derive(AxumErrorResponse)]`) so
    /// it can be returned directly from [`authenticate`] and [`authorize`];
    /// each variant's `#[status_code]`/`#[code]` attributes determine the
    /// resulting HTTP status and JSON error body.
    #[derive(Debug, thiserror::Error, axum_error_handler::AxumErrorResponse)]
    pub enum AppError {
        /// Missing, malformed, or invalid/expired bearer token; responds
        /// with `401 Unauthorized`.
        #[error("Bearer token in authorization header is missing or invalid!")]
        #[status_code("401")]
        #[code("UNAUTHORIZED")]
        Unauthorized,

        /// Token is valid but the authenticated user lacks the role
        /// required for this resource; responds with `403 Forbidden`.
        #[error("Permissions to act on this resource are insufficient!")]
        #[status_code("403")]
        #[code("FORBIDDEN")]
        Forbidden,
    }
}

/// Integration and unit tests for [`config`], [`handlers`], [`items`], and
/// [`auth`].
#[cfg(test)]
mod tests {
    /// Tests for [`crate::config::AppConfig`] and [`crate::config::run_app`].
    mod config {
        use crate::config::{AppConfig, AppError};
        use cool_asserts::assert_matches;
        use figment::Jail;
        use test_case::test_case;

        #[test_case(
            "success", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"), // key_file
            Some("test-secret"); // jwt_secret
            "success"
        )]
        #[test_case(
            "failed_find_http_addr_env_var", // scenario
            None, // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_find_http_addr_env_var"
        )]
        #[test_case(
            "failed_find_https_addr_env_var", // scenario
            Some("127.0.0.1:3080"), // http_addr
            None, // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_find_https_addr_env_var"
        )]
        #[test_case(
            "failed_find_cert_path_env_var", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            None, // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_find_cert_path_env_var"
        )]
        #[test_case(
            "failed_find_key_path_env_var", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            None, // key_path
            Some("a"), // crt_file
            Some("a"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_find_key_path_env_var"
        )]
        #[test_case(
            "failed_parse_http_socket_addr", // scenario
            Some(""), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_parse_http_socket_addr"
        )]
        #[test_case(
            "failed_parse_https_socket_addr", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some(""), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_parse_https_socket_addr"
        )]
        #[test_case(
            "failed_open_public_key_file", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            None, // crt_file
            Some("a"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_open_public_key_file"
        )]
        #[test_case(
            "failed_read_public_key_file", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("-----BEGIN PUBLIC KEY-----"), // crt_file
            Some("a"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_read_public_key_file"
        )]
        #[test_case(
            "failed_find_public_keys", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some(""), // crt_file
            Some("a"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_find_public_keys"
        )]
        #[test_case(
            "failed_open_private_key_file", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            None, // key_file
            Some("test-secret"); // jwt_secret
            "failed_open_private_key_file"
        )]
        #[test_case(
            "failed_read_private_key_file", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("-----BEGIN PRIVATE KEY-----"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_read_private_key_file"
        )]
        #[test_case(
            "failed_find_private_keys", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some(""), // key_file
            Some("test-secret"); // jwt_secret
            "failed_find_private_keys"
        )]
        #[test_case(
            "failed_config_tls", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("b"), // key_file
            Some("test-secret"); // jwt_secret
            "failed_config_tls"
        )]
        #[test_case(
            "failed_find_jwt_secret_env_var", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"), // key_file
            None; // jwt_secret
            "failed_find_jwt_secret_env_var"
        )]
        /// Exercises every success/failure path of [`AppConfig::new`] by
        /// populating a jailed environment and filesystem, then asserting
        /// the resulting [`AppError`] variant (or success) matches
        /// `scenario`.
        fn test_create_appconfig(
            scenario: &str,
            http_addr: Option<&str>,
            https_addr: Option<&str>,
            cert_path: Option<&str>,
            key_path: Option<&str>,
            crt_file: Option<&str>,
            key_file: Option<&str>,
            jwt_secret: Option<&str>,
        ) {
            let _ = Jail::try_with(|jail| {
                let key_pair_a =
                    rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
                let key_pair_b =
                    rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();

                jail.clear_env();

                if let Some(data) = http_addr {
                    jail.set_env("HTTP_ADDR", data);
                }

                if let Some(data) = https_addr {
                    jail.set_env("HTTPS_ADDR", data);
                }

                if let Some(data) = cert_path {
                    jail.set_env("CERT_PATH", data);
                }

                if let Some(data) = key_path {
                    jail.set_env("KEY_PATH", data);
                }

                if let Some(data) = jwt_secret {
                    jail.set_env("JWT_SECRET", data);
                }

                if let Some(data) = crt_file {
                    match data {
                        "a" => {
                            jail.create_file("test.crt", key_pair_a.cert.pem().as_str())?;
                        }
                        "b" => {
                            jail.create_file("test.crt", key_pair_b.cert.pem().as_str())?;
                        }
                        _ => {
                            jail.create_file("test.crt", data)?;
                        }
                    }
                }

                if let Some(data) = key_file {
                    match data {
                        "a" => {
                            jail.create_file(
                                "test.key",
                                key_pair_a.signing_key.serialize_pem().as_str(),
                            )?;
                        }
                        "b" => {
                            jail.create_file(
                                "test.key",
                                key_pair_b.signing_key.serialize_pem().as_str(),
                            )?;
                        }
                        _ => {
                            jail.create_file("test.key", data)?;
                        }
                    }
                }

                let result = tokio_test::block_on(AppConfig::new());

                match scenario {
                    "success" => assert_matches!(result, Ok(_)),
                    "failed_find_http_addr_env_var" => {
                        assert_matches!(result, Err(AppError::FailedFindEnvVar(_, _)))
                    }
                    "failed_find_https_addr_env_var" => {
                        assert_matches!(result, Err(AppError::FailedFindEnvVar(_, _)))
                    }
                    "failed_find_cert_path_env_var" => {
                        assert_matches!(result, Err(AppError::FailedFindEnvVar(_, _)))
                    }
                    "failed_find_key_path_env_var" => {
                        assert_matches!(result, Err(AppError::FailedFindEnvVar(_, _)))
                    }
                    "failed_find_jwt_secret_env_var" => {
                        assert_matches!(result, Err(AppError::FailedFindEnvVar(_, _)))
                    }
                    "failed_parse_http_socket_addr" => {
                        assert_matches!(result, Err(AppError::FailedParseSocketAddr(_, _)))
                    }
                    "failed_parse_https_socket_addr" => {
                        assert_matches!(result, Err(AppError::FailedParseSocketAddr(_, _)))
                    }
                    "failed_open_public_key_file" => {
                        assert_matches!(result, Err(AppError::FailedOpenPublicKeyFile(_, _)))
                    }
                    "failed_read_public_key_file" => {
                        assert_matches!(result, Err(AppError::FailedReadPublicKeyFile(_, _)))
                    }
                    "failed_find_public_keys" => {
                        assert_matches!(result, Err(AppError::FailedFindPublicKeys(_)))
                    }
                    "failed_open_private_key_file" => {
                        assert_matches!(result, Err(AppError::FailedOpenPrivateKeyFile(_, _)))
                    }
                    "failed_read_private_key_file" => {
                        assert_matches!(result, Err(AppError::FailedReadPrivateKeyFile(_, _)))
                    }
                    "failed_find_private_keys" => {
                        assert_matches!(result, Err(AppError::FailedFindPrivateKeys(_)))
                    }
                    "failed_config_tls" => {
                        assert_matches!(result, Err(AppError::FailedConfigTLS(_, _)))
                    }
                    _ => unreachable!(),
                }

                Ok(())
            });
        }
    }
    /// Tests for [`crate::config::run_app`]'s startup/shutdown lifecycle.
    mod run_app {
        use crate::config::{self, AppConfig, AppError, AppState};
        use axum_server::tls_rustls::RustlsConfig;
        use cool_asserts::assert_matches;
        use rcgen::generate_simple_self_signed;
        use secrecy::SecretString;
        use std::{
            net::{IpAddr, Ipv4Addr, SocketAddr},
            sync::Arc,
        };
        use tokio::sync::oneshot;

        /// Builds a self-signed [`AppState`] bound to OS-assigned
        /// (`:0`) loopback ports, suitable for use in tests.
        async fn test_state() -> AppState {
            let key_pair = generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();

            let tls_config = RustlsConfig::from_der(
                vec![key_pair.cert.der().to_vec()],
                key_pair.signing_key.serialize_der(),
            )
            .await
            .unwrap();

            AppState {
                config: AppConfig {
                    http_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                    https_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                    cert_path: "test.crt".into(),
                    key_path: "test.key".into(),
                    tls_config: Arc::new(tls_config),
                    jwt_secret: SecretString::from("test-secret".to_string()),
                },
                items: Arc::new(dashmap::DashMap::new()),
                roles: Arc::new(dashmap::DashMap::new()),
                cache: crate::cache::CacheState::new(),
            }
        }

        /// Verifies that [`config::run_app`] completes successfully once
        /// its shutdown signal resolves.
        #[test_log::test(tokio::test)]
        async fn test_run_app_success() {
            let state = test_state().await;

            let (shutdown_tx, shutdown_rx) = oneshot::channel();

            let task = tokio::spawn(config::run_app(state, async move {
                shutdown_rx
                    .await
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
            }));

            tokio::task::yield_now().await;

            shutdown_tx.send(()).unwrap();

            let result = task.await.unwrap();

            assert_matches!(result, Ok(()));
        }

        /// Verifies that [`config::run_app`] returns
        /// [`AppError::FailedInitCtrlC`] when the shutdown signal future
        /// itself resolves to an `Err`.
        #[test_log::test(tokio::test)]
        async fn test_run_app_failure_init_shutdown_signal() {
            let state = test_state().await;

            let result = config::run_app(state, async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "test initialize shutdown signal failure",
                ))
            })
            .await;

            assert_matches!(result, Err(AppError::FailedInitCtrlC(_)));
        }

        /// Verifies that [`config::run_app`] keeps running (does not
        /// complete) until its shutdown signal resolves.
        #[test_log::test(tokio::test)]
        async fn test_run_app_success_waits_for_shutdown_signal() {
            let state = test_state().await;

            let (shutdown_tx, shutdown_rx) = oneshot::channel();

            let task = tokio::spawn(config::run_app(state, async move {
                shutdown_rx
                    .await
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
            }));

            tokio::task::yield_now().await;

            assert!(!task.is_finished());

            shutdown_tx.send(()).unwrap();

            assert_matches!(task.await.unwrap(), Ok(()));
        }
    }
    /// Tests for the handlers in [`crate::handlers`].
    mod handlers {
        use crate::{
            config::{self, AppState},
            handlers,
        };
        use axum::http::StatusCode;
        use axum_test::TestServer;

        /// Builds a [`TestServer`] wrapping the router produced by
        /// `router_fn` over a fresh [`AppState`].
        async fn test_server(router_fn: fn(AppState) -> axum::Router) -> TestServer {
            let state = AppState::new().await.unwrap();

            TestServer::new(router_fn(state))
        }

        /// Verifies that any request to the HTTP router is redirected to
        /// the equivalent HTTPS URL via [`handlers::redirect_to_https`].
        #[test_log::test(tokio::test)]
        async fn test_redirect_to_https_success() {
            let server = test_server(config::http_router).await;

            let response = server.get("/healthz").await;

            response.assert_status(StatusCode::TEMPORARY_REDIRECT);

            response.assert_header("location", "https://127.0.0.1:3443/healthz");
        }

        /// Verifies that [`handlers::check_app_liveliness`] resolves
        /// successfully.
        #[test_log::test(tokio::test(start_paused = true))]
        async fn test_check_app_liveliness() {
            let task = tokio::spawn(handlers::check_app_liveliness());

            tokio::time::advance(std::time::Duration::from_secs(1)).await;

            assert!(task.await.unwrap().is_ok());
        }

        /// Verifies that an unmatched HTTPS route falls through to
        /// [`handlers::report_route_invalid`] with a `404` status.
        #[test_log::test(tokio::test)]
        async fn test_report_route_invalid_success() {
            let server = test_server(config::https_router).await;

            let response = server.get("/").await;

            response.assert_status(StatusCode::NOT_FOUND);
        }
    }
    /// Tests for the item API in [`crate::items`], including the
    /// [`crate::auth`] middleware and [`crate::cache`] middleware layered
    /// onto it.
    mod items {
        use crate::{
            auth::Claims,
            config::{self, AppState},
            items::Item,
        };
        use axum::http::StatusCode;
        use axum_test::TestServer;
        use jsonwebtoken::{EncodingKey, Header, encode};
        use secrecy::ExposeSecret;
        use serde_json::{Value, json};
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        use test_case::test_case;
        use uuid::Uuid;

        /// Encodes a JWT for `sub`, signed with the app's own configured
        /// secret, so it validates against whatever `JWT_SECRET` the test
        /// environment has set.
        fn mint_token(state: &AppState, sub: &str) -> String {
            let exp = (SystemTime::now() + Duration::from_secs(3600))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize;

            let claims = Claims {
                sub: sub.to_string(),
                exp,
            };

            encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(state.config.jwt_secret.expose_secret().as_bytes()),
            )
            .unwrap()
        }

        /// Adds a Bearer `Authorization` header to a test request.
        fn bearer(token: &str) -> (axum::http::HeaderName, axum::http::HeaderValue) {
            (
                axum::http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            )
        }

        /// Builds a [`TestServer`] wrapping the router produced by
        /// `router_fn`, pre-populated with two [`Item`]s (one keyed by
        /// [`Uuid::nil`], one keyed by a random [`Uuid`]) and a seeded
        /// [`RoleStore`](crate::auth::RoleStore). Returns the server
        /// alongside an admin token (roles: admin, user) and a plain user
        /// token (roles: user).
        async fn test_server(
            router_fn: fn(AppState) -> axum::Router,
        ) -> (TestServer, String, String) {
            let state = AppState::new().await.unwrap();

            state.items.insert(
                Uuid::nil(),
                Item {
                    name: "test".to_string(),
                    desc: "test".to_string(),
                },
            );

            state.items.insert(
                Uuid::new_v4(),
                Item {
                    name: "tset".to_string(),
                    desc: "tset".to_string(),
                },
            );

            state.roles.insert(
                "admin-user".to_string(),
                vec!["admin".to_string(), "user".to_string()],
            );
            state
                .roles
                .insert("plain-user".to_string(), vec!["user".to_string()]);

            let admin_token = mint_token(&state, "admin-user");
            let user_token = mint_token(&state, "plain-user");

            (TestServer::new(router_fn(state)), admin_token, user_token)
        }

        #[test_case(
            json!({"name":"test", "desc":"test"}), // payload
            StatusCode::CREATED; // status
            "success"
        )]
        #[test_case(
            json!({"desc":"test"}), // payload
            StatusCode::UNPROCESSABLE_ENTITY; // status
            "failure_missing_name"
        )]
        #[test_case(
            json!({"name":"", "desc":"test"}), // payload
            StatusCode::BAD_REQUEST; // status
            "failure_invalid_name"
        )]
        #[test_case(
            json!({"name":"test"}), // payload
            StatusCode::UNPROCESSABLE_ENTITY; // status
            "failure_missing_desc"
        )]
        #[test_case(
            json!({"name":"test", "desc":""}), // payload
            StatusCode::BAD_REQUEST; // status
            "failure_invalid_desc"
        )]
        /// Verifies `POST /items` behavior for valid and invalid payloads.
        #[test_log::test(tokio::test)]
        async fn test_create(payload: Value, status: StatusCode) {
            let (server, _admin_token, user_token) = test_server(config::https_router).await;
            let (name, value) = bearer(&user_token);

            let response = server
                .post("/items")
                .add_header(name, value)
                .json(&payload)
                .await;

            response.assert_status(status);

            if status == StatusCode::CREATED {
                let body: Value = response.json();

                assert!(body["id"].is_string());
                assert_eq!(body["item"]["name"], payload["name"]);
                assert_eq!(body["item"]["desc"], payload["desc"]);
            }
        }

        #[test_case(
            Uuid::nil().to_string(), // pathid
            StatusCode::OK; // status
            "success"
        )]
        #[test_case(
            Uuid::new_v4().to_string(), // pathid
            StatusCode::NOT_FOUND; // status
            "failure_missing_id"
        )]
        #[test_case(
            "abc".to_string(), // pathid
            StatusCode::BAD_REQUEST; // status
            "failure_invalid_id"
        )]
        /// Verifies `DELETE /items/{id}` behavior for existing, missing,
        /// and malformed ids, using an admin-privileged token.
        #[test_log::test(tokio::test)]
        async fn test_delete(pathid: String, status: StatusCode) {
            let (server, admin_token, _user_token) = test_server(config::https_router).await;
            let (name, value) = bearer(&admin_token);

            let response = server
                .delete(&format!("/items/{pathid}"))
                .add_header(name, value)
                .await;

            response.assert_status(status);

            if status == StatusCode::OK {
                let body: Value = response.json();

                assert_eq!(body["id"].as_str().unwrap(), pathid);
                assert_eq!(body["item"]["name"], "test");
                assert_eq!(body["item"]["desc"], "test");
            }
        }

        #[test_case(
            Uuid::nil().to_string(), // pathid
            StatusCode::OK; // status
            "success"
        )]
        #[test_case(
            Uuid::new_v4().to_string(), // pathid
            StatusCode::NOT_FOUND; // status
            "failure_missing_id"
        )]
        #[test_case(
            "abc".to_string(), // pathid
            StatusCode::BAD_REQUEST; // status
            "failure_invalid_id"
        )]
        /// Verifies `GET /items/{id}` behavior for existing, missing, and
        /// malformed ids.
        #[test_log::test(tokio::test)]
        async fn test_get(pathid: String, status: StatusCode) {
            let (server, _admin_token, user_token) = test_server(config::https_router).await;
            let (name, value) = bearer(&user_token);

            let response = server
                .get(&format!("/items/{pathid}"))
                .add_header(name, value)
                .await;

            response.assert_status(status);

            if status == StatusCode::OK {
                let body: Value = response.json();

                assert_eq!(body["id"].as_str().unwrap(), pathid);
                assert_eq!(body["item"]["name"], "test");
                assert_eq!(body["item"]["desc"], "test");
            }
        }

        #[test_case(
        "".to_string(), // queryparams
        2, // length
        StatusCode::OK; // status
        "success_no_filter"
        )]
        #[test_case(
        "name=test".to_string(), // queryparams
        1, // length
        StatusCode::OK; // status
        "success_filter_name"
        )]
        #[test_case(
        "name=test&desc=tset".to_string(), // queryparams
        0, // length
        StatusCode::OK; // status
        "success_filter_name_and_desc"
        )]
        #[test_case(
        "name=".to_string(), // queryparams
        0, // length
        StatusCode::BAD_REQUEST; // status
        "failure_missing_filter"
        )]
        /// Verifies `GET /items` filtering behavior across `name`/`desc`
        /// query parameters, including validation failures.
        #[test_log::test(tokio::test)]
        async fn test_select(queryparams: String, length: usize, status: StatusCode) {
            let (server, _admin_token, user_token) = test_server(config::https_router).await;
            let (name, value) = bearer(&user_token);

            let response = server
                .get(&format!("/items?{queryparams}"))
                .add_header(name, value)
                .await;

            response.assert_status(status);

            if status == StatusCode::OK {
                let body: Vec<Value> = response.json();

                assert_eq!(body.len(), length);
            }
        }

        #[test_case(
            Uuid::nil().to_string(), // pathid
            json!({"name":"updated", "desc":"updated",}), // payload
            StatusCode::OK; // status
            "success_update_name_and_desc"
        )]
        #[test_case(
            Uuid::nil().to_string(), // pathid
            json!({"name":"updated",}), // payload
            StatusCode::OK; // status
            "success_update_name"
        )]
        #[test_case(
            Uuid::nil().to_string(), // pathid
            json!({"desc":"updated",}), // payload
            StatusCode::OK; // status
            "success_update_desc"
        )]
        #[test_case(
            Uuid::new_v4().to_string(), // pathid
            json!({"name":"updated", "desc":"updated",}), // payload
            StatusCode::NOT_FOUND; // status
            "failure_missing_id"
        )]
        #[test_case(
            "abc".to_string(), // pathid
            json!({"name": "updated", "desc": "updated",}), // payload
            StatusCode::BAD_REQUEST; // status
            "failure_invalid_id"
        )]
        /// Verifies `PUT /items/{id}` partial-update behavior for
        /// existing, missing, and malformed ids.
        #[test_log::test(tokio::test)]
        async fn test_update(pathid: String, payload: Value, status: StatusCode) {
            let (server, _admin_token, user_token) = test_server(config::https_router).await;
            let (name, value) = bearer(&user_token);

            let response = server
                .put(&format!("/items/{pathid}"))
                .add_header(name, value)
                .json(&payload)
                .await;

            response.assert_status(status);

            if status == StatusCode::OK {
                let body: Value = response.json();

                assert_eq!(body["id"].as_str().unwrap(), pathid);
                if payload.get("name").is_some() {
                    assert_eq!(body["item"]["name"], payload["name"],);
                }
                if payload.get("desc").is_some() {
                    assert_eq!(body["item"]["desc"], payload["desc"],);
                }
            }
        }

        /// Verifies a request with no `Authorization` header is rejected
        /// before it ever reaches a handler.
        #[test_log::test(tokio::test)]
        async fn test_items_failure_unauthenticated() {
            let (server, _admin_token, _user_token) = test_server(config::https_router).await;

            let response = server.get("/items").await;

            response.assert_status(StatusCode::UNAUTHORIZED);
        }

        /// Verifies an authenticated non-admin user is forbidden from
        /// `DELETE /items/{id}`, distinct from the "item not found" case.
        #[test_log::test(tokio::test)]
        async fn test_delete_failure_forbidden_non_admin() {
            let (server, _admin_token, user_token) = test_server(config::https_router).await;
            let (name, value) = bearer(&user_token);

            let response = server
                .delete(&format!("/items/{}", Uuid::nil()))
                .add_header(name, value)
                .await;

            response.assert_status(StatusCode::FORBIDDEN);
        }

        /// Verifies that a repeated `GET /items/{id}` is served from the
        /// [`crate::cache`] layer: after the first request populates the
        /// cache, a direct mutation of the underlying store (bypassing the
        /// API entirely) is not reflected in the second response.
        #[test_log::test(tokio::test)]
        async fn test_get_success_served_from_cache() {
            let state = AppState::new().await.unwrap();
            let id = Uuid::nil();

            state.items.insert(
                id,
                Item {
                    name: "test".to_string(),
                    desc: "test".to_string(),
                },
            );
            state
                .roles
                .insert("plain-user".to_string(), vec!["user".to_string()]);

            let user_token = mint_token(&state, "plain-user");
            let items = state.items.clone();

            let server = TestServer::new(config::https_router(state));
            let (name, value) = bearer(&user_token);

            let first = server
                .get(&format!("/items/{id}"))
                .add_header(name.clone(), value.clone())
                .await;
            first.assert_status(StatusCode::OK);

            // Mutate the store directly, bypassing PUT, so a fresh (non-cached)
            // response would differ from what was already returned above.
            items.insert(
                id,
                Item {
                    name: "changed".to_string(),
                    desc: "changed".to_string(),
                },
            );

            let second = server
                .get(&format!("/items/{id}"))
                .add_header(name, value)
                .await;
            second.assert_status(StatusCode::OK);

            assert_eq!(first.text(), second.text());
        }

        /// Verifies that `POST /items` is never served from the cache:
        /// two identical creation requests each insert a distinct item.
        #[test_log::test(tokio::test)]
        async fn test_create_success_bypasses_cache() {
            let (server, _admin_token, user_token) = test_server(config::https_router).await;
            let (name, value) = bearer(&user_token);
            let payload = json!({"name":"dup", "desc":"dup"});

            let first = server
                .post("/items")
                .add_header(name.clone(), value.clone())
                .json(&payload)
                .await;
            first.assert_status(StatusCode::CREATED);

            let second = server
                .post("/items")
                .add_header(name, value)
                .json(&payload)
                .await;
            second.assert_status(StatusCode::CREATED);

            let first_body: Value = first.json();
            let second_body: Value = second.json();

            assert_ne!(first_body["id"], second_body["id"]);
        }
    }
    /// Tests for [`crate::auth`], exercised against a minimal standalone
    /// router rather than the full [`crate::config::https_router`].
    mod auth {
        use crate::auth::{self, AuthState, AuthUser, Claims, RoleStore};
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

        /// A minimal protected router: `authenticate` guards everything,
        /// and `/admin` additionally requires the "admin" role via
        /// `authorize`. Seeded with "alice" (admin + user) and "bob" (user
        /// only).
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
                    auth::authorize("admin", ext, req, next)
                }));

            let app = Router::new()
                .route(
                    "/me",
                    get(|Extension(user): Extension<AuthUser>| async move { user.user_id }),
                )
                .merge(admin_only)
                .layer(middleware::from_fn_with_state(
                    auth_state,
                    auth::authenticate,
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
        async fn test_authenticate_failure_malformed_header() {
            let response = test_server()
                .get("/me")
                .add_header(axum::http::header::AUTHORIZATION, "not-a-bearer-token")
                .await;

            response.assert_status(StatusCode::UNAUTHORIZED);
        }

        /// Verifies a token signed with a different secret is rejected.
        #[test_log::test(tokio::test)]
        async fn test_authenticate_failure_invalid_signature() {
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
    /// Tests for [`crate::cache`], exercised against a minimal standalone
    /// router rather than the full [`crate::config::https_router`].
    mod cache {
        use crate::cache::{self, CacheState};
        use axum::{
            Router,
            http::StatusCode,
            middleware,
            routing::{get, post},
        };
        use axum_test::TestServer;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        /// A minimal router with one GET route (counts each time it's
        /// actually invoked) wrapped in [`cache::cache_response`], and one
        /// POST route left unwrapped for comparison.
        fn test_server() -> (TestServer, Arc<AtomicUsize>) {
            let hits = Arc::new(AtomicUsize::new(0));
            let counter = hits.clone();

            let cache_state = CacheState::new();

            let app = Router::new()
                .route(
                    "/counter",
                    get(move || {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            "response"
                        }
                    }),
                )
                .route("/uncached", post(|| async { "response" }))
                .layer(middleware::from_fn_with_state(
                    cache_state,
                    cache::cache_response,
                ));

            (TestServer::new(app), hits)
        }

        /// Verifies a second identical `GET` is served from the cache: the
        /// underlying handler only actually runs once, and the `x-cache`
        /// header reports `MISS` then `HIT`.
        #[test_log::test(tokio::test)]
        async fn test_cache_response_success_get_methods() {
            let (server, hits) = test_server();

            let first = server.get("/counter").await;
            let second = server.get("/counter").await;

            first.assert_status(StatusCode::OK);
            first.assert_header("x-cache", "MISS");
            second.assert_status(StatusCode::OK);
            second.assert_header("x-cache", "HIT");
            assert_eq!(first.text(), second.text());
            assert_eq!(hits.load(Ordering::SeqCst), 1);
        }

        /// Verifies non-`GET` requests always reach the handler, never the
        /// cache, and are left without an `x-cache` header.
        #[test_log::test(tokio::test)]
        async fn test_cache_response_success_non_get_methods() {
            let (server, hits) = test_server();

            let first = server.post("/uncached").await;
            let second = server.post("/uncached").await;

            first.assert_status(StatusCode::OK);
            second.assert_status(StatusCode::OK);
            assert!(!first.headers().contains_key("x-cache"));
            assert_eq!(hits.load(Ordering::SeqCst), 0);
        }

        /// Verifies distinct query strings on the same path are cached
        /// under distinct keys (i.e. the query string is part of the key,
        /// not just the path).
        #[test_log::test(tokio::test)]
        async fn test_cache_response_success_distinct_query_params() {
            let (server, hits) = test_server();

            server
                .get("/counter?a=1")
                .await
                .assert_status(StatusCode::OK);
            server
                .get("/counter?a=2")
                .await
                .assert_status(StatusCode::OK);
            server
                .get("/counter?a=1")
                .await
                .assert_status(StatusCode::OK);

            // Two distinct query strings -> two underlying handler calls;
            // the repeat of "?a=1" is served from the cache.
            assert_eq!(hits.load(Ordering::SeqCst), 2);
        }

        /// Verifies query parameters in a different order are treated as
        /// the *same* cache key (parameters are sorted before keying).
        #[test_log::test(tokio::test)]
        async fn test_cache_response_success_indistinct_query_params() {
            let (server, hits) = test_server();

            let first = server.get("/counter?a=1&b=2").await;
            let second = server.get("/counter?b=2&a=1").await;

            first.assert_status(StatusCode::OK);
            first.assert_header("x-cache", "MISS");
            second.assert_status(StatusCode::OK);
            second.assert_header("x-cache", "HIT");
            assert_eq!(first.text(), second.text());
            assert_eq!(hits.load(Ordering::SeqCst), 1);
        }
    }
}
