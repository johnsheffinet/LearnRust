#[tokio::main]
async fn main() -> config::AppResult<()> {
    use crate::config::AppState;
    use tokio_util::{sync::CancellationToken, task::TaskTracker};

    tracing_subscriber::fmt::init();

    // config::run(async {
    //     tokio::signal::ctrl_c()
    //         .await
    //         .expect("Failed to initialize Ctrl+C interceptor!");
    // })
    // .await

    tracing::info!("Building AppState and AppConfig...");

    let state = AppState::new().await?;
    let http_state = state.clone();
    let https_state = state.clone();
    let config = state.config.clone();
    let http_config = config.clone();
    let https_config = config.clone();
    let token = CancellationToken::new();
    let tracker = TaskTracker::new();

    config::spawn_server(
        "HTTP",
        http_config.http_addr,
        move |handle| {
            axum_server::bind(http_config.http_addr)
                .handle(handle)
                .serve(config::http_router(http_state).into_make_service())
        },
        token.child_token(),
        &tracker,
    );

    config::spawn_server(
        "HTTPS",
        https_config.https_addr,
        move |handle| {
            axum_server::bind_rustls(https_config.https_addr, (*config.tls_config).clone())
                .handle(handle)
                .serve(config::https_router(https_state).into_make_service())
        },
        token.child_token(),
        &tracker,
    );

    tokio::signal::ctrl_c()
        .await
        .expect("Failed to initialize Ctrl+C interceptor!");

    tracing::info!("\n[Main] Intercepted shutdown signal! Cancelling child tokens...");
    token.cancel();

    tracker.close();

    tracing::info!("[Main] Waiting until all services gracefully stop...");
    tracker.wait().await;

    tracing::info!("[Main] Stopped all services. Exiting process cleanly...");
    Ok(())
}

pub mod config {
    use crate::{
        handlers,
        items::{self, Item},
    };
    use axum::{Router, extract::FromRef};
    use axum_server::{Handle, tls_rustls::RustlsConfig};
    use dashmap::DashMap;
    use rustls_pki_types::pem::PemObject;
    use std::{env, future::Future, net::SocketAddr, path::PathBuf, sync::Arc};
    use tokio_util::{sync::CancellationToken, task::TaskTracker};
    use uuid::Uuid;

    pub fn spawn_server<F, B>(
        name: &'static str,
        addr: SocketAddr,
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

                tracing::info!("[{name}] Stopping service on {addr}...");

                handle.graceful_shutdown(None);
            }
        });

        tracker.spawn({
            let handle = handle.clone();

            async move {
                tracing::info!("[{name}] Starting service on {addr}...");

                let server = builder(handle);

                if let Err(err) = server.await {
                    tracing::error!("[{name}] {err}");
                }

                tracing::info!("[{name}] Stopped service on {addr}.");
            }
        });
    }

    #[derive(Clone, Debug, FromRef)]
    pub struct AppState {
        pub config: AppConfig,
        pub items: AppStore<Item>,
    }

    impl AppState {
        #[tracing::instrument(skip_all, err)]
        pub async fn new() -> AppResult<Self> {
            let config = AppConfig::new().await?;
            let items = DashMap::new();

            Ok(Self { config, items })
        }
    }

    pub type AppStore<T> = DashMap<Uuid, T>;

    pub fn http_router(state: AppState) -> Router {
        Router::new()
            .fallback(handlers::redirect_to_https)
            .with_state(state)
    }

    pub fn https_router(state: AppState) -> Router {
        use axum::routing::get;

        Router::new()
            .merge(items::routes::<AppState>())
            .route("/healthz", get(handlers::check_app_liveliness))
            .fallback(handlers::report_route_invalid)
            .with_state(state)
    }

    #[derive(Clone, Debug)]
    pub struct AppConfig {
        pub http_addr: SocketAddr,
        pub https_addr: SocketAddr,
        pub cert_path: PathBuf,
        pub key_path: PathBuf,
        pub tls_config: Arc<RustlsConfig>,
    }

    impl AppConfig {
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

            Ok(Self {
                http_addr,
                https_addr,
                cert_path,
                key_path,
                tls_config,
            })
        }
    }

    pub type AppResult<T> = Result<T, AppError>;

    #[derive(Debug, thiserror::Error)]
    pub enum AppError {
        #[error("Failed to find environment variable {1}! {0}")]
        FailedFindEnvVar(#[source] std::env::VarError, String),

        #[error("Failed to parse socket address {1}! {0}")]
        FailedParseSocketAddr(#[source] std::net::AddrParseError, String),

        #[error("Failed to open public key file {1}! {0}")]
        FailedOpenPublicKeyFile(#[source] std::io::Error, PathBuf),

        #[error("Failed to read public key file {1}! {0}")]
        FailedReadPublicKeyFile(#[source] rustls_pki_types::pem::Error, PathBuf),

        #[error("Failed to find public keys in PEM file {0}!")]
        FailedFindPublicKeys(PathBuf),

        #[error("Failed to open private key file {1}! {0}")]
        FailedOpenPrivateKeyFile(#[source] std::io::Error, PathBuf),

        #[error("Failed to read private key file {1}! {0}")]
        FailedReadPrivateKeyFile(#[source] rustls_pki_types::pem::Error, PathBuf),

        #[error("Failed to find private keys in PEM file {0}!")]
        FailedFindPrivateKeys(PathBuf),

        #[error("Failed to configure TLS from file {1}! {0}")]
        FailedConfigTLS(#[source] std::io::Error, PathBuf),
    }
}
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

    #[tracing::instrument(skip_all, err)]
    pub async fn redirect_to_https(
        State(state): State<AppState>,
        uri: Uri,
    ) -> AppResult<impl IntoResponse> {
        let addr = &state.config.https_addr;

        let path_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let redirect_url = format!("https://{addr}{path_query}");

        let location =
            HeaderValue::try_from(redirect_url.clone()).map_err(AppError::FailedCreateHeader)?;

        Ok((
            StatusCode::TEMPORARY_REDIRECT,
            [(LOCATION, location)],
            Json(json!({"status": format!("Temporarily redirecting to {redirect_url}.")})),
        ))
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn check_app_liveliness() -> AppResult<impl IntoResponse> {
        // use tokio::time::{Duration, sleep};

        // sleep(Duration::from_secs(10)).await;

        Ok((StatusCode::OK, Json(json!({"status": "App is lively."}))))
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn report_route_invalid(uri: Uri) -> AppResult<impl IntoResponse> {
        let path = uri.path();
        Ok((
            StatusCode::NOT_FOUND,
            Json(json!({"status": format!("Invalid route {path}.")})),
        ))
    }

    type AppResult<T> = Result<T, AppError>;

    #[derive(Debug, thiserror::Error, axum_error_handler::AxumErrorResponse)]
    pub enum AppError {
        #[error("Failed to create header! {0}")]
        #[status_code("400")]
        FailedCreateHeader(InvalidHeaderValue),
    }
}
pub mod items {
    use crate::config::AppStore;
    use axum::{
        extract::{Json, Path, Query, State},
        http::StatusCode,
        response::IntoResponse,
    };
    use axum_valid::Valid;
    use uuid::Uuid;

    pub fn routes<S>() -> axum::Router<S>
    where
        AppStore<Item>: axum::extract::FromRef<S>,
        S: Clone + Send + Sync + 'static,
    {
        axum::Router::new()
            .route("/items", axum::routing::get(select).post(create))
            .route(
                "/items/{id}",
                axum::routing::get(get).delete(delete).put(update),
            )
    }

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

    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct CreateJsonPayload {
        #[validate(length(min = 1, message = "field in create json payload is missing!"))]
        name: String,
        #[validate(length(min = 1, message = "field in create json payload is missing!"))]
        desc: String,
    }

    impl From<CreateJsonPayload> for Item {
        fn from(payload: CreateJsonPayload) -> Self {
            Self {
                name: payload.name,
                desc: payload.desc,
            }
        }
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Item {
        pub name: String,
        pub desc: String,
    }

    impl Item {
        fn edit(&mut self, payload: UpdateJsonPayload) {
            if let Some(name) = payload.name {
                self.name = name;
            }
            if let Some(desc) = payload.desc {
                self.desc = desc;
            }
        }
    }

    #[derive(Debug, serde::Serialize)]
    struct ItemResponse {
        id: Uuid,
        item: Item,
    }

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

    #[derive(Debug, serde::Deserialize)]
    pub struct GetPathId {
        id: Uuid,
    }

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

    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct SelectQueryParams {
        #[validate(length(min = 1, message = "field in select query params is missing!"))]
        name: Option<String>,
        #[validate(length(min = 1, message = "field in select query params is missing!"))]
        desc: Option<String>,
    }

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

    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct UpdateJsonPayload {
        #[validate(length(min = 1, message = "field in update json payload is missing!"))]
        name: Option<String>,
        #[validate(length(min = 1, message = "field in update json payload is missing!"))]
        desc: Option<String>,
    }

    pub type AppResult<T> = Result<T, AppError>;

    #[derive(Debug, thiserror::Error, axum_error_handler::AxumErrorResponse)]
    pub enum AppError {
        #[error("Failed to validate request! {0}")]
        #[status_code("422")]
        #[code("UNPROCESSABLE_ENTITY")]
        UnprocessableEntity(#[from] validator::ValidationErrors),

        #[error("Failed to find {0} id in request path!")]
        #[status_code("404")]
        #[code("NOT_FOUND")]
        NotFound(String),
    }
}
#[cfg(test)]
mod tests {
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
            Some("a"); // key_file
            "success"
        )]
        #[test_case(
            "failed_find_http_addr_env_var", // scenario
            None, // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"); // key_file
            "failed_find_http_addr_env_var"
        )]
        #[test_case(
            "failed_find_https_addr_env_var", // scenario
            Some("127.0.0.1:3080"), // http_addr
            None, // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"); // key_file
            "failed_find_https_addr_env_var"
        )]
        #[test_case(
            "failed_find_cert_path_env_var", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            None, // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"); // key_file
            "failed_find_cert_path_env_var"
        )]
        #[test_case(
            "failed_find_key_path_env_var", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            None, // key_path
            Some("a"), // crt_file
            Some("a"); // key_file
            "failed_find_key_path_env_var"
        )]
        #[test_case(
            "failed_parse_http_socket_addr", // scenario
            Some(""), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"); // key_file
            "failed_parse_http_socket_addr"
        )]
        #[test_case(
            "failed_parse_https_socket_addr", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some(""), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("a"); // key_file
            "failed_parse_https_socket_addr"
        )]
        #[test_case(
            "failed_open_public_key_file", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            None, // crt_file
            Some("a"); // key_file
            "failed_open_public_key_file"
        )]
        #[test_case(
            "failed_read_public_key_file", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("-----BEGIN PUBLIC KEY-----"), // crt_file
            Some("a"); // key_file
            "failed_read_public_key_file"
        )]
        #[test_case(
            "failed_find_public_keys", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some(""), // crt_file
            Some("a"); // key_file
            "failed_find_public_keys"
        )]
        #[test_case(
            "failed_open_private_key_file", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            None; // key_file
            "failed_open_private_key_file"
        )]
        #[test_case(
            "failed_read_private_key_file", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("-----BEGIN PRIVATE KEY-----"); // key_file
            "failed_read_private_key_file"
        )]
        #[test_case(
            "failed_find_private_keys", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some(""); // key_file
            "failed_find_private_keys"
        )]
        #[test_case(
            "failed_config_tls", // scenario
            Some("127.0.0.1:3080"), // http_addr
            Some("127.0.0.1:3443"), // https_addr
            Some("test.crt"), // cert_path
            Some("test.key"), // key_path
            Some("a"), // crt_file
            Some("b"); // key_file
            "failed_config_tls"
        )]
        fn test_create_appconfig(
            scenario: &str,
            http_addr: Option<&str>,
            https_addr: Option<&str>,
            cert_path: Option<&str>,
            key_path: Option<&str>,
            crt_file: Option<&str>,
            key_file: Option<&str>,
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
    mod handlers {
        use crate::{
            config::{self, AppState},
            handlers,
        };
        use axum::http::StatusCode;
        use axum_test::TestServer;

        async fn test_server(router_fn: fn(AppState) -> axum::Router) -> TestServer {
            let state = AppState::new().await.unwrap();

            TestServer::new(router_fn(state))
        }

        #[test_log::test(tokio::test)]
        async fn test_redirect_to_https_success() {
            let server = test_server(config::http_router).await;

            let response = server.get("/healthz").await;

            response.assert_status(StatusCode::TEMPORARY_REDIRECT);

            response.assert_header("location", "https://127.0.0.1:3443/healthz");
        }

        #[test_log::test(tokio::test(start_paused = true))]
        async fn test_check_app_liveliness() {
            let task = tokio::spawn(handlers::check_app_liveliness());

            tokio::time::advance(std::time::Duration::from_secs(1)).await;

            assert!(task.await.unwrap().is_ok());
        }

        #[test_log::test(tokio::test)]
        async fn test_report_route_invalid_success() {
            let server = test_server(config::https_router).await;

            let response = server.get("/").await;

            response.assert_status(StatusCode::NOT_FOUND);
        }
    }
    mod items {
        use crate::{
            config::{self, AppState},
            items::Item,
        };
        use axum::http::StatusCode;
        use axum_test::TestServer;
        use serde_json::{Value, json};
        use test_case::test_case;
        use uuid::Uuid;

        async fn test_server(router_fn: fn(AppState) -> axum::Router) -> TestServer {
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

            TestServer::new(router_fn(state))
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
        #[test_log::test(tokio::test)]
        async fn test_create(payload: Value, status: StatusCode) {
            let server = test_server(config::https_router).await;

            let response = server.post("/items").json(&payload).await;

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
        #[test_log::test(tokio::test)]
        async fn test_delete(pathid: String, status: StatusCode) {
            let server = test_server(config::https_router).await;

            let response = server.delete(&format!("/items/{pathid}")).await;

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
        #[test_log::test(tokio::test)]
        async fn test_get(pathid: String, status: StatusCode) {
            let server = test_server(config::https_router).await;

            let response = server.get(&format!("/items/{pathid}")).await;

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
        #[test_log::test(tokio::test)]
        async fn test_select(queryparams: String, length: usize, status: StatusCode) {
            let server = test_server(config::https_router).await;

            let response = server.get(&format!("/items?{queryparams}")).await;

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
        #[test_log::test(tokio::test)]
        async fn test_update(pathid: String, payload: Value, status: StatusCode) {
            let server = test_server(config::https_router).await;

            let response = server.put(&format!("/items/{pathid}")).json(&payload).await;

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
    }
}
