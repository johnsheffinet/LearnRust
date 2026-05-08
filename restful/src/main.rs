pub mod config {
    use axum_server::tls_rustls::RustlsConfig;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use std::sync::LazyLock;

    pub static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| AppConfig::new().unwrap());

    #[derive(Debug, thiserror::Error)]
    pub enum AppError {
        #[error("Failed to find '{1}' environment variable! {0}")]
        FailedFindEnvVar(#[source] std::env::VarError, String),

        #[error("Failed to parse '{1}' socket address {0}")]
        FailedParseSocketAddr(#[source] std::net::AddrParseError, String),

        #[error("Failed to open {1} PEM file! {0}")]
        FailedOpenPEMFile(#[source] rustls_pki_types::pem::Error, std::path::PathBuf),

        #[error("Failed to parse {1} PEM file! {0}")]
        FailedParsePEMFile(#[source] rustls_pki_types::pem::Error, std::path::PathBuf),

        #[error("Failed to find valid certificates in '{0}' PEM file!")]
        FailedFindCerts(std::path::PathBuf),

        #[error("Failed to configure TLS from '{1}' file! {0}")]
        FailedConfigTLS(#[source] std::io::Error, std::path::PathBuf),
    }

    pub type AppResult<T> = Result<T, AppError>;

    #[derive(Debug)]
    pub struct AppConfig {
        pub http_addr: std::net::SocketAddr,
        pub https_addr: std::net::SocketAddr,
        pub cert_path: std::path::PathBuf,
        pub key_path: std::path::PathBuf,
        pub tls_config: RustlsConfig,
        pub http_router: axum::Router,
        pub https_router: axum::Router,
    }

    impl AppConfig {
        #[tracing::instrument(skip_all, err)]
        pub fn new() -> AppResult<AppConfig> {
            use crate::handlers as h;
            use axum::routing::get;

            let http_addr_raw = std::env::var("HTTP_ADDR")
                .map_err(|s| AppError::FailedFindEnvVar(s, "HTTP_ADDR".into()))?;
            let http_addr = http_addr_raw
                .parse::<std::net::SocketAddr>()
                .map_err(|s| AppError::FailedParseSocketAddr(s, http_addr_raw))?;

            let https_addr_raw = std::env::var("HTTPS_ADDR")
                .map_err(|s| AppError::FailedFindEnvVar(s, "HTTPS_ADDR".into()))?;
            let https_addr = https_addr_raw
                .parse::<std::net::SocketAddr>()
                .map_err(|s| AppError::FailedParseSocketAddr(s, https_addr_raw))?;

            let cert_path_raw = std::env::var("CERT_PATH")
                .map_err(|s| AppError::FailedFindEnvVar(s, "CERT_PATH".into()))?;
            let cert_path = std::path::PathBuf::from(cert_path_raw);

            let certs = CertificateDer::pem_file_iter(&cert_path)
                .map_err(|s| AppError::FailedOpenPEMFile(s, cert_path.clone()))?
                .map(|r| r.map_err(|s| AppError::FailedParsePEMFile(s, cert_path.clone())))
                .collect::<Result<Vec<_>, _>>()?;

            if certs.is_empty() {
                return Err(AppError::FailedFindCerts(cert_path));
            }

            let key_path_raw = std::env::var("KEY_PATH")
                .map_err(|s| AppError::FailedFindEnvVar(s, "KEY_PATH".into()))?;
            let key_path = std::path::PathBuf::from(key_path_raw);
            let key = PrivateKeyDer::from_pem_file(&key_path)
                .map_err(|s| AppError::FailedOpenPEMFile(s, key_path.clone()))?;

            let tls_config = futures::executor::block_on(RustlsConfig::from_der(
                certs.into_iter().map(|c| c.to_vec()).collect(),
                key.secret_der().to_vec(),
            ))
            .map_err(|s| AppError::FailedConfigTLS(s, cert_path.clone()))?;

            let http_router = axum::Router::new().fallback(h::redirect_to_https);

            let https_router = axum::Router::new()
                .route("/healthz", get(h::check_app_liveliness))
                .fallback(h::report_invalid_route);

            Ok(AppConfig {
                http_addr,
                https_addr,
                cert_path,
                key_path,
                tls_config,
                http_router,
                https_router,
            })
        }
    }
}
pub mod handlers {
    use axum::response::IntoResponse;

    #[derive(Debug, thiserror::Error, axum_thiserror::ErrorStatus)]
    pub enum AppError {
        #[error("Failed to create header! {0}")]
        #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
        FailedCreateHeader(axum::http::header::InvalidHeaderValue),
    }

    type AppResult<T> = Result<T, AppError>;

    #[tracing::instrument(skip_all, err)]
    pub async fn redirect_to_https(
        req: axum::extract::Request,
    ) -> AppResult<axum::response::Response> {
        use crate::config::CONFIG;
        use axum::http::header::LOCATION;

        let status = axum::http::StatusCode::TEMPORARY_REDIRECT;

        let path_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let https_addr = CONFIG.https_addr;
        let location =
            axum::http::HeaderValue::try_from(&format!("https://{https_addr}{path_query}"))
                .map_err(AppError::FailedCreateHeader)?;

        let body = axum::Json(
            serde_json::json!({ "status": format!("Temporarily redirecting to {location:?}.") }),
        );

        Ok((status, [(LOCATION, location)], body).into_response())
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn check_app_liveliness() -> AppResult<axum::response::Response> {
        let status = axum::http::StatusCode::OK;

        let body = axum::Json(serde_json::json!({ "status": "App is lively." }));

        Ok((status, body).into_response())
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn report_invalid_route(uri: axum::http::Uri) -> AppResult<axum::response::Response> {
        let status = axum::http::StatusCode::NOT_FOUND;

        let path = uri.path();
        let body =
            axum::Json(serde_json::json!({ "status": format!("'{path}' route is invalid!") }));

        Ok((status, body).into_response())
    }
}
pub mod items {
    use axum::{extract::{Json, Path, Query, State}, http::StatusCode, response::{IntoResponse, Response},};
    use axum_valid::Valid;
    // use std::sync::Arc;
    // use tokio::sync::RwLock;
    // use std::collections::HashMap;
    // use uuid::Uuid;
    
    #[derive(Debug, thiserror::Error, axum_error_handler::AxumErrorResponse)]
    pub enum AppError {
        #[error("Failed to validate!")]
        #[status_code("422")]
        #[code("FAILED_VALIDATE")]
        FailedValidate(#[from] validator::ValidationErrors),
    }

    pub type AppResult<T> = Result<T, AppError>;

    // pub type AppState = Arc<Rwlock<HashMap<Uuid, AppStore>>>;
    
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub struct Item {
        id: uuid::Uuid,
        name: String,
        desc: String,
    }

    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct CreateBody {
        #[validate(length(min = 1, message = "Name field in create body is missing!"))]
        name: String,
        #[validate(length(min = 1, message = "Desc field in create body is missing!"))]
        desc: String,
    }

    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct UpdateBody {
        #[validate(length(min = 1, message = "Name field in update body is missing!"))]
        name: Option<String>,
        #[validate(length(min = 1, message = "Desc field in update body is missing!"))]
        desc: Option<String>,
    }

    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct SelectAllQuery {
        #[validate(length(min = 1, message = "Name field in selectall query parameters is missing!"))]
        name: Option<String>,
        #[validate(length(min = 1, message = "Desc field in selectall query parameters is missing!"))]
        desc: Option<String>,
    }

    #[derive(Debug, serde::Deserialize, validator::Validate)]
    pub struct IdPath {
        #[validate(
            custom(function = "IdPath::validate_is_v4"),
            custom(function = "IdPath::validate_not_nil"),
        )]
        id: uuid::Uuid,
    }

    impl IdPath {
        fn validate_is_v4(id: &uuid::Uuid) -> Result<(), validator::ValidationError> {
            if id.get_version_num() != 4 {
                Err(validator::ValidationError::new("Id field in path parameter is invalid!"))
            }

            Ok(())
        }

        fn validate_not_nil(id: &uuid::Uuid) -> Result<(), validator::ValidationError> {
            if id.is_nil() {
                Err(validator::ValidationError::new("Id field in path parameter is nil!"))
            }

            Ok(())
        }
    }


    // use std::collections::HashMap;
    // use validator::ValidationErrors;
    
    // async fn into_hashmap(errors: ValidationErrors) -> HashMap<String, Vec<String>> {
    //     errors
    //         .field_errors()
    //         .into_iter()
    //         .map(|(field, field_errors)| {
    //             let messages = field_errors
    //                 .into_iter()
    //                 .map(|error| {
    //                     error.message
    //                         .map(|m| m.into_owned())
    //                         .unwrap_or_else(|| format!("Failed to parse {field}!"))
    //                 })
    //                 .collect();
    //             (field.to_string(), messages)
    //         })
    //         .collect()
    // })
    
    #[tracing::instrument(skip_all, err)]
    pub async fn create(
        Json(payload): Json<CreatePayload>,
        State(app_state): State<AppState>,
    ) -> AppResult<Response> {
        payload.validate()?;

        let app_store = AppStore {
            id: Uuid::new_v4(),
            name: payload.name,
            desc: payload.value,
        };

        let db = app_state.write().await;
        db.insert(app_store.id, app_store.clone());

        Ok((StatusCode::CREATED, Json(app_store)).into_response())
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn delete(
        Path(id): Path<Uuid>,
        State(app_state): State<AppState>,
    ) -> AppResult<axum::response::Response> {}

    #[tracing::instrument(skip_all, err)]
    pub async fn select_all(
        Query(query): Query<SelectQuery>,
        State(app_state): State<AppState>,
    ) -> AppResult<axum::response::Response> {}

    #[tracing::instrument(skip_all, err)]
    pub async fn select_one(
        Path(id): Path<Uuid>,
        State(app_state): State<AppState>,
    ) -> AppResult<axum::response::Response> {}

    #[tracing::instrument(skip_all, err)]
    pub async fn update(
        Path(id): Path<Uuid>,
        Json(payload): Json<UpdatePayload>,
        State(app_state): State<Appstate>,
    ) -> AppResult<axum::response::Response> {} 
}
pub mod tools {
    use axum::extract::FromRequest;

    #[derive(Debug, thiserror::Error, axum_thiserror::ErrorStatus)]
    pub enum AppError {
        #[error("Failed to serialize payload parameter into request body! {0}")]
        #[status(axum::http::StatusCode::BAD_REQUEST)]
        FailedSerializePayloadIntoRequest(#[source] serde_json::Error),

        #[error("Failed to serialize payload parameter from request body! {0}")]
        #[status(axum::http::StatusCode::BAD_REQUEST)]
        FailedSerializePayloadFromRequest(#[source] serde_json::Error),

        #[error("Failed to build request body from payload parameter! {0}")]
        #[status(axum::http::StatusCode::BAD_REQUEST)]
        FailedBuildRequestFromPayload(#[source] axum::http::Error),

        #[error("Failed to parse request body into payload parameter! {0}")]
        #[status(axum::http::StatusCode::BAD_REQUEST)]
        FailedParseRequestIntoPayload(#[source] axum::Error),

        #[error("Failed to serialize payload parameter into response body! {0}")]
        #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
        FailedSerializePayloadIntoResponse(#[source] serde_json::Error),

        #[error("Failed to serialize payload parameter from response body! {0}")]
        #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
        FailedSerializePayloadFromResponse(#[source] serde_json::Error),

        #[error("Failed to build response body from payload parameter! {0}")]
        #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
        FailedBuildResponseFromPayload(#[source] axum::http::Error),

        #[error("Failed to parse response body into payload parameter! {0}")]
        #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
        FailedParseResponseIntoPayload(#[source] axum::Error),

        #[error("Failed to get router response parameters from request parameters! {0}")]
        #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
        FailedGetRouterResponse(String),
    }

    pub type AppResult<T> = Result<T, AppError>;

    #[derive(Debug, Clone, PartialEq)]
    pub struct RequestParams {
        pub method: axum::http::Method,
        pub path: String,
        pub query: String,
        pub version: axum::http::Version,
        pub headers: axum::http::HeaderMap,
        pub payload: serde_json::Value,
    }

    impl TryFrom<RequestParams> for axum::extract::Request {
        type Error = AppError;

        #[tracing::instrument(skip_all, err)]
        fn try_from(params: RequestParams) -> Result<Self, Self::Error> {
            let params_uri = if params.query.is_empty() {
                params.path
            } else {
                format!("{}?{}", params.path, params.query)
            };

            let mut builder = axum::extract::Request::builder()
                .method(params.method)
                .uri(params_uri)
                .version(params.version);

            if let Some(headers) = builder.headers_mut() {
                headers.extend(params.headers);
            }

            let body = serde_json::to_vec(&params.payload)
                .map_err(AppError::FailedSerializePayloadIntoRequest)?;

            builder
                .body(axum::body::Body::from(body))
                .map_err(AppError::FailedBuildRequestFromPayload)
        }
    }

    impl<S> FromRequest<S> for RequestParams
    where
        S: Send + Sync,
    {
        type Rejection = AppError;

        #[tracing::instrument(skip_all, err)]
        async fn from_request(
            req: axum::extract::Request,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            let method = req.method().clone();

            let uri = req.uri().clone();

            let path = uri.path().to_string();

            let query = uri.query().unwrap_or("").to_string();

            let version = req.version();

            let headers = req.headers().clone();

            let body = axum::body::to_bytes(req.into_body(), 2 * 1024 * 1024)
                .await
                .map_err(AppError::FailedParseRequestIntoPayload)?;
            let payload = serde_json::from_slice(&body)
                .map_err(AppError::FailedSerializePayloadFromRequest)?;

            Ok(RequestParams {
                method,
                path,
                query,
                version,
                headers,
                payload,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ResponseParams {
        pub version: axum::http::Version,
        pub status: axum::http::StatusCode,
        pub headers: axum::http::HeaderMap,
        pub payload: serde_json::Value,
    }

    impl TryFrom<ResponseParams> for axum::response::Response {
        type Error = AppError;

        #[tracing::instrument(skip_all, err)]
        fn try_from(params: ResponseParams) -> Result<Self, Self::Error> {
            let mut builder = axum::response::Response::builder()
                .version(params.version)
                .status(params.status);

            if let Some(headers) = builder.headers_mut() {
                headers.extend(params.headers);
            }

            let body = serde_json::to_vec(&params.payload)
                .map_err(AppError::FailedSerializePayloadIntoResponse)?;

            builder
                .body(axum::body::Body::from(body))
                .map_err(AppError::FailedBuildResponseFromPayload)
        }
    }

    impl ResponseParams {
        #[tracing::instrument(skip_all, err)]
        pub async fn from_response(res: axum::response::Response) -> AppResult<Self> {
            let version = res.version();

            let status = res.status();

            let headers = res.headers().clone();

            let body = axum::body::to_bytes(res.into_body(), 2 * 1024 * 1024)
                .await
                .map_err(AppError::FailedParseResponseIntoPayload)?;
            let payload = serde_json::from_slice(&body)
                .map_err(AppError::FailedSerializePayloadFromResponse)?;

            Ok(ResponseParams {
                version,
                status,
                headers,
                payload,
            })
        }
    }

    #[tracing::instrument(skip_all, err)]
    pub async fn get_router_response_params(
        router: axum::Router,
        req_params: RequestParams,
    ) -> AppResult<ResponseParams> {
        use tower::util::ServiceExt;

        let req = axum::extract::Request::try_from(req_params)?;

        let res = router
            .oneshot(req)
            .await
            .map_err(|err| AppError::FailedGetRouterResponse(err.to_string()))?;

        let res_params = ResponseParams::from_response(res).await?;

        Ok(res_params)
    }
}
#[cfg(test)]
mod tests {
    mod config {
        use crate::config::{AppConfig, AppError};
        use test_case::test_case;

        #[test_case(Some("valid"),   Some("valid"),   Some("valid"),   "Success";               "success")]
        #[test_case(None,            Some("valid"),   Some("valid"),   "FailedFindEnvVar";      "failure find env var")]
        #[test_case(Some("invalid"), Some("valid"),   Some("valid"),   "FailedParseSocketAddr"; "failure parse socket addr")]
        #[test_case(Some("valid"),   None,            Some("valid"),   "FailedOpenPEMFile";     "failure open pem file")]
        #[test_case(Some("valid"),   Some("bad_pem"), Some("valid"),   "FailedParsePEMFile";    "failure parse pem file")]
        #[test_case(Some("valid"),   Some("no_cert"), Some("valid"),   "FailedFindCerts";       "failure find certs")]
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
                    "FailedOpenPEMFile" => cool_asserts::assert_matches!(
                        AppConfig::new(),
                        Err(AppError::FailedOpenPEMFile(_, _))
                    ),
                    "FailedParsePEMFile" => cool_asserts::assert_matches!(
                        AppConfig::new(),
                        Err(AppError::FailedParsePEMFile(_, _))
                    ),
                    "FailedFindCerts" => cool_asserts::assert_matches!(
                        AppConfig::new(),
                        Err(AppError::FailedFindCerts(_))
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
    mod tools {
        use crate::tools::{AppError, RequestParams, ResponseParams};
        use axum::extract::FromRequest;

        #[test_log::test(tokio::test)]
        async fn test_create_request_from_params_success() {
            use axum::http::header::{CONTENT_TYPE, HeaderValue};

            let method = axum::http::Method::GET;

            let path = "/".to_string();

            let query = "key1=value1&key2=value2".to_string();

            let version = axum::http::Version::HTTP_11;

            let mut headers = axum::http::header::HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

            let payload = serde_json::json!({ "key1": "value1", "key2": "value2" });

            let expected_params = RequestParams {
                method,
                path,
                query,
                version,
                headers,
                payload,
            };

            let req = cool_asserts::assert_matches!(axum::extract::Request::try_from(expected_params.clone()), Ok(req) => req);

            let actual_params = cool_asserts::assert_matches!(RequestParams::from_request(req, &()).await, Ok(actual_params) => actual_params);

            pretty_assertions::assert_eq!(actual_params, expected_params);
        }

        #[test_log::test(tokio::test)]
        async fn test_create_request_from_params_failure_invalid_path() {
            use axum::http::header::{CONTENT_TYPE, HeaderValue};

            let method = axum::http::Method::GET;

            let path = "/invalid path".to_string();

            let query = "".to_string();

            let version = axum::http::Version::HTTP_11;

            let mut headers = axum::http::header::HeaderMap::new();

            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

            let payload = serde_json::json!({});

            let expected_params = RequestParams {
                method,
                path,
                query,
                version,
                headers,
                payload,
            };

            cool_asserts::assert_matches!(
                axum::extract::Request::try_from(expected_params.clone()),
                Err(AppError::FailedBuildRequestFromPayload(_))
            );
        }

        #[test_log::test(tokio::test)]
        async fn test_create_request_from_params_failure_invalid_query() {
            use axum::http::header::{CONTENT_TYPE, HeaderValue};

            let method = axum::http::Method::GET;

            let path = "/".to_string();

            let query = "invalid query".to_string();

            let version = axum::http::Version::HTTP_11;

            let mut headers = axum::http::header::HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

            let payload = serde_json::json!({});

            let expected_params = RequestParams {
                method,
                path,
                query,
                version,
                headers,
                payload,
            };

            cool_asserts::assert_matches!(axum::extract::Request::try_from(expected_params.clone()), Err(AppError::FailedBuildRequestFromPayload(ref err)) => {
                pretty_assertions::assert_eq!(err.to_string(), "invalid uri character");
            });
        }

        #[test_log::test(tokio::test)]
        async fn test_create_response_from_params_success() {
            let version = axum::http::Version::HTTP_11;

            let status = axum::http::StatusCode::OK;

            let mut headers = axum::http::header::HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::header::HeaderValue::from_static("application/json"),
            );

            let payload = serde_json::json!({ "key": "value" });

            let expected_params = ResponseParams {
                version,
                status,
                headers,
                payload,
            };

            let res = cool_asserts::assert_matches!(axum::response::Response::try_from(expected_params.clone()), Ok(res) => res);

            let actual_params = cool_asserts::assert_matches!(ResponseParams::from_response(res).await, Ok(actual_params) => actual_params);

            pretty_assertions::assert_eq!(actual_params, expected_params);
        }
    }
    mod handlers {
        use std::str::FromStr;

        #[test_case::test_case(
            "Http",
            axum::http::Method::GET,
            "/healthz",
            "",
            axum::http::Version::HTTP_11,
            vec![("Content-Type", "application/json")],
            serde_json::json!({}),
            axum::http::StatusCode::TEMPORARY_REDIRECT,
            vec![("Content-Type", "application/json"), ("Location", "https://127.0.0.1:3443/healthz"), ("Content-Length", "75")],
            serde_json::json!({ "status": format!("Temporarily redirecting to {:?}.", "https://127.0.0.1:3443/healthz") });
            "redirect to https success"
        )]
        #[test_case::test_case(
            "Https",
            axum::http::Method::GET,
            "/healthz",
            "",
            axum::http::Version::HTTP_11,
            vec![],
            serde_json::json!({}),
            axum::http::StatusCode::OK,
            vec![("Content-Type", "application/json"), ("Content-Length", "27")],
            serde_json::json!({ "status": "App is lively." });
            "check app liveliness success"
        )]
        #[test_case::test_case(
            "Https",
            axum::http::Method::GET,
            "/invalid",
            "",
            axum::http::Version::HTTP_11,
            vec![],
            serde_json::json!({}),
            axum::http::StatusCode::NOT_FOUND,
            vec![("Content-Type", "application/json"), ("Content-Length", "41")],
            serde_json::json!({ "status": "'/invalid' route is invalid!" });
            "report invalid route success"
        )]
        #[test_log::test(tokio::test)]
        async fn test_handlers(
            router_type: &'static str,
            method: axum::http::Method,
            path: &'static str,
            query: &'static str,
            version: axum::http::Version,
            req_headers: Vec<(&'static str, &'static str)>,
            req_payload: serde_json::Value,
            status: axum::http::StatusCode,
            res_headers: Vec<(&'static str, &'static str)>,
            res_payload: serde_json::Value,
        ) {
            let router = match router_type {
                "Http" => crate::config::CONFIG.http_router.clone(),
                "Https" => crate::config::CONFIG.https_router.clone(),
                _ => panic!("Didn't expect {} router type!", router_type),
            };

            let into_headermap = |headers: Vec<(&str, &str)>| -> axum::http::header::HeaderMap {
                headers
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            axum::http::header::HeaderName::from_str(k)
                                .expect(&format!("Failed to parse '{k}' key into header name!")),
                            axum::http::header::HeaderValue::from_str(v)
                                .expect(&format!("Failed to parse '{v}' value into header value!")),
                        )
                    })
                    .collect()
            };

            let req_params = crate::tools::RequestParams {
                method,
                path: path.to_string(),
                query: query.to_string(),
                version,
                headers: into_headermap(req_headers),
                payload: req_payload,
            };

            let actual_res_params = crate::tools::get_router_response_params(router, req_params)
                .await
                .expect("Failed to get response parameters!");

            let expected_res_params = crate::tools::ResponseParams {
                version,
                status,
                headers: into_headermap(res_headers),
                payload: res_payload,
            };

            pretty_assertions::assert_eq!(actual_res_params, expected_res_params);
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    std::sync::LazyLock::force(&config::CONFIG);
}
