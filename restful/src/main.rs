#![warn(unused_crate_dependencies)]

pub mod states {
    #[derive(Clone, Debug)]
    pub struct AppStates {
        items: AppState<Item>,
    }

    impl AppStates {
        pub fn new() -> Self {
            Self {
                items: Arc::new(dashmap::DashMap::new()),
            }
        }
    }

    pub type AppState<T> = Arc<dashmap::DashMap<uuid::Uuid, T>>;

    pub fn http_router(config: Arc<AppConfig>) -> Router<()> {
        Router::new()
            .fallback(handlers::redirect_to_https)
            .with_state(config)
    }

    pub fn https_router(states: AppStates) -> Router<AppStates> {
        Router::new()
            .merge(items::routes::<AppStates>())
            .route(
                "/healthz",
                axum::routing::get(handlers::check_app_liveliness),
            )
            .fallback(handlers::report_invalid_route)
            .with_state(states)
    }

    #[derive(Clone, Debug)]
    pub struct AppStates {
        pub config: ,
        pub items: ,
    }

    impl AppStates {}

    pub type AppState<T> = Arc<DashMap<Uuid, T>>;

    pub fn http_routes() -> Router {}

    pub fn https_routes() -> Router<AppState<Item>> {}
}
pub mod config {
    use crate::{
        handlers,
        items::{self, Item},
    };
    use axum::{Router, extract::FromRef};
    use axum_server::tls_rustls::RustlsConfig;
    use rustls_pki_types::pem::PemObject;
    use std::sync::Arc;

    #[derive(Clone, Debug)]
    pub struct AppConfig {
        pub http_addr: std::net::SocketAddr,
        pub https_addr: std::net::SocketAddr,
        pub cert_path: std::path::PathBuf,
        pub key_path: std::path::PathBuf,
        pub tls_config: RustlsConfig,
    }

    impl AppConfig {
        #[tracing::instrument(skip_all, err)]
        pub fn new() -> AppResult<AppConfig> {
            let http_addr_raw = std::env::var("HTTP_ADDR")
                .map_err(|src| AppError::FailedFindEnvVar(src, "HTTP_ADDR".into()))?;
            let http_addr = http_addr_raw
                .parse::<std::net::SocketAddr>()
                .map_err(|src| AppError::FailedParseSocketAddr(src, http_addr_raw))?;

            let https_addr_raw = std::env::var("HTTPS_ADDR")
                .map_err(|src| AppError::FailedFindEnvVar(src, "HTTPS_ADDR".into()))?;
            let https_addr = https_addr_raw
                .parse::<std::net::SocketAddr>()
                .map_err(|src| AppError::FailedParseSocketAddr(src, https_addr_raw))?;

            let cert_path_raw = std::env::var("CERT_PATH")
                .map_err(|src| AppError::FailedFindEnvVar(src, "CERT_PATH".into()))?;
            let cert_path = std::path::PathBuf::from(cert_path_raw);

            let certs = rustls_pki_types::CertificateDer::pem_file_iter(&cert_path)
                .map_err(|src| AppError::FailedOpenPublicKeyFile(src, cert_path.clone()))?
                .map(|result| {
                    result.map_err(|src| AppError::FailedReadPublicKeyFile(src, cert_path.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if certs.is_empty() {
                return Err(AppError::FailedFindPublicKeys(cert_path));
            }

            let key_path_raw = std::env::var("KEY_PATH")
                .map_err(|src| AppError::FailedFindEnvVar(src, "KEY_PATH".into()))?;
            let key_path = std::path::PathBuf::from(key_path_raw);

            let key_pem_file = std::fs::read(&key_path)
                .map_err(|src| AppError::FailedOpenPrivateKeyFile(src, key_path.clone()))?;
            let key = rustls_pki_types::PrivateKeyDer::pem_slice_iter(&key_pem_file)
                .next()
                .ok_or_else(|| AppError::FailedFindPrivateKeys(key_path.clone()))?
                .map_err(|src| AppError::FailedReadPrivateKeyFile(src, key_path.clone()))?;

            let tls_config = tokio::runtime::Runtime::new()
                .map_err(|src| AppError::FailedConfigTLS(src, cert_path.clone()))?
                .block_on(RustlsConfig::from_der(
                    certs.into_iter().map(|cert| cert.to_vec()).collect(),
                    key.secret_der().to_vec(),
                ))
                .map_err(|src| AppError::FailedConfigTLS(src, cert_path.clone()))?;

            Ok(AppConfig {
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
        FailedOpenPublicKeyFile(#[source] rustls_pki_types::pem::Error, std::path::PathBuf),

        #[error("Failed to read public key file {1}! {0}")]
        FailedReadPublicKeyFile(#[source] rustls_pki_types::pem::Error, std::path::PathBuf),

        #[error("Failed to find public keys in PEM file {0}!")]
        FailedFindPublicKeys(std::path::PathBuf),

        #[error("Failed to open private key file {1}! {0}")]
        FailedOpenPrivateKeyFile(#[source] std::io::Error, std::path::PathBuf),

        #[error("Failed to read private key file {1}! {0}")]
        FailedReadPrivateKeyFile(#[source] rustls_pki_types::pem::Error, std::path::PathBuf),

        #[error("Failed to find private keys in PEM file {0}!")]
        FailedFindPrivateKeys(std::path::PathBuf),

        #[error("Failed to configure TLS from file {1}! {0}")]
        FailedConfigTLS(#[source] std::io::Error, std::path::PathBuf),
    }
}
pub mod handlers {
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
    use std::sync::Arc;

    #[tracing::instrument(skip_all, err)]
    pub async fn redirect_to_https(
        State(config): State<crate::config::AppConfig>,
        uri: Uri,
    ) -> AppResult<impl IntoResponse> {
        let path_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let redirect_url = format!("https://{}{}", config.https_addr, path_query,);

        let location =
            HeaderValue::try_from(redirect_url.clone()).map_err(AppError::FailedCreateHeader)?;

        Ok((
            StatusCode::TEMPORARY_REDIRECT,
            [(LOCATION, location)],
            Json(json!({"status": format!("Temporarily redirecting to {}.", redirect_url)})),
        ))
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn check_app_liveliness() -> AppResult<impl IntoResponse> {
        Ok((StatusCode::OK, Json(json!({"status": "App is lively."}))))
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn report_invalid_route(uri: Uri) -> AppResult<impl IntoResponse> {
        Ok((
            StatusCode::NOT_FOUND,
            Json(json!({"status": format!("Invalid route {}!", uri.path())})),
        ))
    }

    type AppResult<T> = Result<T, AppError>;

    #[derive(Debug, thiserror::Error, axum_thiserror::ErrorStatus)]
    pub enum AppError {
        #[error("Failed to create header! {0}")]
        #[status(StatusCode::INTERNAL_SERVER_ERROR)]
        FailedCreateHeader(InvalidHeaderValue),
    }
}
pub mod items {
    use crate::config::AppState;
    use axum::{
        extract::{Json, Path, Query, State},
        http::StatusCode,
        response::IntoResponse,
    };
    use axum_valid::Valid;
    use std::sync::Arc;

    pub fn routes<S>() -> axum::Router<S>
    where
        AppState<Item>: axum::extract::FromRef<S>,
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
        State(state): State<AppState<Item>>,
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

    #[tracing::instrument(skip_all, err)]
    pub async fn delete(
        State(state): State<AppState<Item>>,
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

    #[tracing::instrument(skip_all, err)]
    pub async fn get(
        State(state): State<AppState<Item>>,
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
        State(state): State<AppState<Item>>,
        Valid(Query(params)): Valid<Query<SelectQueryParams>>,
    ) -> AppResult<impl IntoResponse> {
        let results: Vec<ItemResponse> = state
            .iter()
            .filter_map(|entry| {
                let item = entry.value();

                if let Some(ref filter_name) = params.name {
                    if !item.name.contains(filter_name) {
                        return None;
                    }
                }

                if let Some(ref filter_desc) = params.desc {
                    if !item.desc.contains(filter_desc) {
                        return None;
                    }
                }

                Some(ItemResponse {
                    id: *entry.key(),
                    item: (*item).clone(),
                })
            })
            .collect();

        Ok((StatusCode::OK, Json(results)))
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn update(
        State(state): State<AppState<Item>>,
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

    pub type AppResult<T> = Result<T, AppError>;

    #[derive(Debug, thiserror::Error, axum_error_handler::AxumErrorResponse)]
    pub enum AppError {
        #[error("Failed to validate request! {0}")]
        #[status_code(StatusCode::UNPROCESSABLE_ENTITY)]
        #[code("UNPROCESSABLE_ENTITY")]
        UnprocessableEntity(#[from] validator::ValidationErrors),

        #[error("Failed to find {0} id in request path!")]
        #[status_code(StatusCode::NOT_FOUND)]
        #[code("NOT_FOUND")]
        NotFound(String),

        #[error("Failed to process request! {0}")]
        #[status_code(StatusCode::INTERNAL_SERVER_ERROR)]
        #[code("INTERNAL_SERVER_ERROR")]
        InternalServerError(String),
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct Item {
        name: String,
        desc: String,
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
        id: uuid::Uuid,
        item: Item,
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

    #[derive(Debug, serde::Deserialize)]
    pub struct GetPathId {
        id: uuid::Uuid,
    }

    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct SelectQueryParams {
        #[validate(length(min = 1, message = "field in select query params is missing!"))]
        name: Option<String>,
        #[validate(length(min = 1, message = "field in select query params is missing!"))]
        desc: Option<String>,
    }

    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct UpdateJsonPayload {
        #[validate(length(min = 1, message = "field in update json payload is missing!"))]
        name: Option<String>,
        #[validate(length(min = 1, message = "field in update json payload is missing!"))]
        desc: Option<String>,
    }
}
// pub mod tools {
//     use axum::extract::FromRequest;

//     #[derive(Debug, thiserror::Error, axum_thiserror::ErrorStatus)]
//     pub enum AppError {
//         #[error("Failed to serialize payload parameter into request body! {0}")]
//         #[status(axum::http::StatusCode::BAD_REQUEST)]
//         FailedSerializePayloadIntoRequest(#[source] serde_json::Error),

//         #[error("Failed to serialize payload parameter from request body! {0}")]
//         #[status(axum::http::StatusCode::BAD_REQUEST)]
//         FailedSerializePayloadFromRequest(#[source] serde_json::Error),

//         #[error("Failed to build request body from payload parameter! {0}")]
//         #[status(axum::http::StatusCode::BAD_REQUEST)]
//         FailedBuildRequestFromPayload(#[source] axum::http::Error),

//         #[error("Failed to parse request body into payload parameter! {0}")]
//         #[status(axum::http::StatusCode::BAD_REQUEST)]
//         FailedParseRequestIntoPayload(#[source] axum::Error),

//         #[error("Failed to serialize payload parameter into response body! {0}")]
//         #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
//         FailedSerializePayloadIntoResponse(#[source] serde_json::Error),

//         #[error("Failed to serialize payload parameter from response body! {0}")]
//         #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
//         FailedSerializePayloadFromResponse(#[source] serde_json::Error),

//         #[error("Failed to build response body from payload parameter! {0}")]
//         #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
//         FailedBuildResponseFromPayload(#[source] axum::http::Error),

//         #[error("Failed to parse response body into payload parameter! {0}")]
//         #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
//         FailedParseResponseIntoPayload(#[source] axum::Error),

//         #[error("Failed to get router response parameters from request parameters! {0}")]
//         #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
//         FailedGetRouterResponse(String),
//     }

//     pub type AppResult<T> = Result<T, AppError>;

//     pub type AppState<T> = Arc<Rwlock<HashMap<Uuid, T>>>;

//     #[derive(Debug, Clone, PartialEq)]
//     pub struct RequestParams {
//         pub method: axum::http::Method,
//         pub path: String,
//         pub query: String,
//         pub version: axum::http::Version,
//         pub headers: axum::http::HeaderMap,
//         pub payload: serde_json::Value,
//     }

//     impl TryFrom<RequestParams> for axum::extract::Request {
//         type Error = AppError;

//         #[tracing::instrument(skip_all, err)]
//         fn try_from(params: RequestParams) -> Result<Self, Self::Error> {
//             let params_uri = if params.query.is_empty() {
//                 params.path
//             } else {
//                 format!("{}?{}", params.path, params.query)
//             };

//             let mut builder = axum::extract::Request::builder()
//                 .method(params.method)
//                 .uri(params_uri)
//                 .version(params.version);

//             if let Some(headers) = builder.headers_mut() {
//                 headers.extend(params.headers);
//             }

//             let body = serde_json::to_vec(&params.payload)
//                 .map_err(AppError::FailedSerializePayloadIntoRequest)?;

//             builder
//                 .body(axum::body::Body::from(body))
//                 .map_err(AppError::FailedBuildRequestFromPayload)
//         }
//     }

//     impl<S> FromRequest<S> for RequestParams
//     where
//         S: Send + Sync,
//     {
//         type Rejection = AppError;

//         #[tracing::instrument(skip_all, err)]
//         async fn from_request(
//             req: axum::extract::Request,
//             _state: &S,
//         ) -> Result<Self, Self::Rejection> {
//             let method = req.method().clone();

//             let uri = req.uri().clone();

//             let path = uri.path().to_string();

//             let query = uri.query().unwrap_or("").to_string();

//             let version = req.version();

//             let headers = req.headers().clone();

//             let body = axum::body::to_bytes(req.into_body(), 2 * 1024 * 1024)
//                 .await
//                 .map_err(AppError::FailedParseRequestIntoPayload)?;
//             let payload = serde_json::from_slice(&body)
//                 .map_err(AppError::FailedSerializePayloadFromRequest)?;

//             Ok(RequestParams {
//                 method,
//                 path,
//                 query,
//                 version,
//                 headers,
//                 payload,
//             })
//         }
//     }

//     #[derive(Debug, Clone, PartialEq)]
//     pub struct ResponseParams {
//         pub version: axum::http::Version,
//         pub status: axum::http::StatusCode,
//         pub headers: axum::http::HeaderMap,
//         pub payload: serde_json::Value,
//     }

//     impl TryFrom<ResponseParams> for axum::response::Response {
//         type Error = AppError;

//         #[tracing::instrument(skip_all, err)]
//         fn try_from(params: ResponseParams) -> Result<Self, Self::Error> {
//             let mut builder = axum::response::Response::builder()
//                 .version(params.version)
//                 .status(params.status);

//             if let Some(headers) = builder.headers_mut() {
//                 headers.extend(params.headers);
//             }

//             let body = serde_json::to_vec(&params.payload)
//                 .map_err(AppError::FailedSerializePayloadIntoResponse)?;

//             builder
//                 .body(axum::body::Body::from(body))
//                 .map_err(AppError::FailedBuildResponseFromPayload)
//         }
//     }

//     impl ResponseParams {
//         #[tracing::instrument(skip_all, err)]
//         pub async fn from_response(res: axum::response::Response) -> AppResult<Self> {
//             let version = res.version();

//             let status = res.status();

//             let headers = res.headers().clone();

//             let body = axum::body::to_bytes(res.into_body(), 2 * 1024 * 1024)
//                 .await
//                 .map_err(AppError::FailedParseResponseIntoPayload)?;
//             let payload = serde_json::from_slice(&body)
//                 .map_err(AppError::FailedSerializePayloadFromResponse)?;

//             Ok(ResponseParams {
//                 version,
//                 status,
//                 headers,
//                 payload,
//             })
//         }
//     }

//     #[tracing::instrument(skip_all, err)]
//     pub async fn get_router_response_params(
//         router: axum::Router,
//         req_params: RequestParams,
//     ) -> AppResult<ResponseParams> {
//         use tower::util::ServiceExt;

//         let req = axum::extract::Request::try_from(req_params)?;

//         let res = router
//             .oneshot(req)
//             .await
//             .map_err(|err| AppError::FailedGetRouterResponse(err.to_string()))?;

//         let res_params = ResponseParams::from_response(res).await?;

//         Ok(res_params)
//     }
// }
#[cfg(test)]
mod tests {
    use crate::config::{AppConfig, AppResult, AppStates, http_router, https_router};
    use axum::{Router, http::StatusCode};
    use axum_test::TestServer;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use test_case::test_case;

    mod config {
        use super::*;
        // use crate::config::AppError;
        // use test_case::test_case;

        #[test_case(Some("valid"),   Some("valid"),   Some("valid"),   "Success";               "success")]
        #[test_case(None,            Some("valid"),   Some("valid"),   "FailedFindEnvVar";      "failure find env var")]
        #[test_case(Some("invalid"), Some("valid"),   Some("valid"),   "FailedParseSocketAddr"; "failure parse socket addr")]
        #[test_case(Some("valid"),   None,            Some("valid"),   "FailedOpenPublicKeyFile";     "failure open pem file")]
        #[test_case(Some("valid"),   Some("bad_pem"), Some("valid"),   "FailedReadPublicKeyFile";    "failure parse pem file")]
        #[test_case(Some("valid"),   Some("no_cert"), Some("valid"),   "FailedFindPublicKeys";       "failure find certs")]
        #[test_case(Some("valid"),   Some("valid"),   Some("invalid"), "FailedConfigTLS";       "failure config tls")]
        #[test_log::test(tokio::test)]
        async fn test_create_app_config(
            addr_param: Option<&str>,
            crt_param: Option<&str>,
            key_param: Option<&str>,
            expected: &str,
        ) {
            figment::Jail::expect_with(|jail| {
                let pair_a = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
                let pair_b = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();

                jail.clear_env();

                if let Some(addr) = addr_param {
                    let data = match addr {
                        "valid" => "127.0.0.1:3080",
                        "invalid" => "",
                        _ => panic!("Did not expect {:?}!", addr),
                    };
                    jail.set_env("HTTP_ADDR", &data);
                }
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "test.crt");
                jail.set_env("KEY_PATH", "test.key");

                if let Some(crt) = crt_param {
                    let data = match crt {
                        "valid" => pair_a.cert.pem(),
                        "bad_pem" => "-----BEGIN PUBLIC KEY-----".to_string(),
                        "no_cert" => "".to_string(),
                        _ => panic!("Did not expect {:?}!", crt),
                    };
                    jail.create_file("test.crt", &data)?;
                }

                if let Some(key) = key_param {
                    let data = match key {
                        "valid" => pair_a.signing_key.serialize_pem(),
                        "invalid" => pair_b.signing_key.serialize_pem(),
                        _ => panic!("Did not expect {:?}!", key),
                    };
                    jail.create_file("test.key", &data)?;
                }

                match expected {
                    "Success" => cool_asserts::assert_matches!(AppConfig::new(), Ok(_)),
                    "FailedFindEnvVar" => cool_asserts::assert_matches!(
                        AppConfig::new(),
                        Err(AppError::FailedFindEnvVar(_, _))
                    ),
                    "FailedParseSocketAddr" => cool_asserts::assert_matches!(
                        AppConfig::new(),
                        Err(AppError::FailedParseSocketAddr(_, _))
                    ),
                    "FailedOpenPublicKeyFile" => cool_asserts::assert_matches!(
                        AppConfig::new(),
                        Err(AppError::FailedOpenPublicKeyFile(_, _))
                    ),
                    "FailedReadPublicKeyFile" => cool_asserts::assert_matches!(
                        AppConfig::new(),
                        Err(AppError::FailedReadPublicKeyFile(_, _))
                    ),
                    "FailedFindPublicKeys" => cool_asserts::assert_matches!(
                        AppConfig::new(),
                        Err(AppError::FailedFindPublicKeys(_))
                    ),
                    "FailedConfigTLS" => cool_asserts::assert_matches!(
                        AppConfig::new(),
                        Err(AppError::FailedConfigTLS(_, _))
                    ),
                    _ => panic!("Did not expect {:?}!", expected),
                }

                Ok(())
            })
        }
    }
    pub mod handlers {
        use super::*;

        #[test_log::test(tokio::test)]
        async fn test_redirect_to_https() {
            let server = TestServer::new(http_router(AppConfig::new())).unwrap();

            let response = server.get("/healthz").await;

            response.assert_status(StatusCode::TEMPORARY_REDIRECT);
        }

        #[test_log::test(tokio::test)]
        async fn test_check_app_liveliness() {
            let server = TestServer::new(https_router(AppStates::new())).unwrap();

            let response = server.get("/healthz").await;

            response.assert_status(StatusCode::OK);
        }

        #[test_log::test(tokio::test)]
        async fn test_report_invalid_route() {
            let server = TestServer::new(https_router(AppStates::new())).unwrap();

            let response = server.get("/").await;

            response.assert_status(StatusCode::NOT_FOUND);
        }
    }
    mod items {
        use axum_test::TestServer;
        use test_case::test_case;

        #[test_case(
            request_payload: Json::Value,
            expected_statuscode: StatusCode,
            expected_response_payload: Json::Value,
        )]
        async fn test_create() {}
        async fn test_delete() {}
        async fn test_get() {}
        async fn test_select() {}
        async fn test_update() {}
    }
}

#[tokio::main]
async fn main() {
    use crate::config::AppConfig;

    tracing_subscriber::fmt::init();

    let cfg = AppConfig::new();
}
