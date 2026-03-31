pub mod config {
    use axum_server::tls_rustls::RustlsConfig;
    use std::sync::LazyLock;

    pub static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| AppConfig::new().expect("Error: "));

    #[derive(Debug, thiserror::Error)]
    pub enum AppError {
        #[error("Failed to find '{1}' environment variable! {0}")]
        FailedFindEnvVar(#[from] std::env::VarError, String),

        #[error("Failed to parse '{1}' socket address {0}")]
        FailedParseSocketAddr(#[from] std::net::AddrParseError, String),

        #[error("Failed to read PEM file! {0}")]
        FailedReadPEMFile(#[from] std::io::Error),
    }

    pub type AppResult<T> = Result<T, AppError>;

    #[derive(Debug)]
    pub struct AppConfig {
        pub http_addr: std::net::SocketAddr,
        pub https_addr: std::net::SocketAddr,
        pub cert_path: std::path::PathBuf,
        pub key_path: std::path::PathBuf,
        pub http_router: axum::Router,
        pub https_router: axum::Router,
        pub tls_config: RustlsConfig,
    }

    impl AppConfig {
        #[tracing::instrument(skip_all, err)]
        pub fn new() -> AppResult<AppConfig> {
            use crate::handlers as h;
            use axum::routing::get;

            let http_addr_val = std::env::var("HTTP_ADDR")
                .map_err(AppError::FailedFindEnvVar, "HTTP_ADDR")?;

            let http_addr = http_addr_val.parse::<std::net::SocketAddr>()
                .map_err(AppError::FailedParseSocketAddr, http_addr_val)?;

            let https_addr_val = std::env::var("HTTPS_ADDR")
                .map_err(AppError::FailedFindEnvVar, "HTTPS_ADDR")?

            let https_addr = https_addr_val.parse::<std::net::SocketAddr>()
                .map_err(AppError::FailedParseSocketAddr, https_addr_val)?;

            let cert_path = std::path::PathBuf::from(std::env::var("CERT_PATH")
                .map_err(AppError::FailedFindEnvVar, "CERT_PATH")?);

            let key_path = std::path::PathBuf::from(std::env::var("KEY_PATH")
                .map_err(AppError::FailedFindEnvVar, "KEY_PATH")?);

            let http_router = axum::Router::new()
                .fallback(h::redirect_to_https);

            let https_router = axum::Router::new()
                .route("/healthz", get(h::check_app_liveliness))
                .fallback(h::report_invalid_route);

            let tls_config =
                futures::executor::block_on(RustlsConfig::from_pem_file(&cert_path, &key_path))?;

            Ok(AppConfig {
                http_addr,
                https_addr,
                cert_path,
                key_path,
                http_router,
                https_router,
                tls_config,
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
        let location = axum::http::HeaderValue::try_from(format!(
            "https://{}{}",
            CONFIG.https_addr, path_query
        ))
        .map_err(AppError::FailedCreateHeader)?;

        let body = axum::Json(
            serde_json::json!({ "status": format!("Temporarily redirecting to {:?}.", location) }),
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
    pub async fn report_invalid_route(
        axum::extract::Path(path): axum::extract::Path<String>,
    ) -> AppResult<axum::response::Response> {
        let status = axum::http::StatusCode::NOT_FOUND;

        let body =
            axum::Json(serde_json::json!({ "status": format!("'{}' route is invalid!", path) }));

        Ok((status, body).into_response())
    }
}
// pub mod tls {
//     use crate::handlers as h;

//     pub async fn get_rustls_config() -> axum_server::tls_rustls::RustlsConfig {
//         use crate::config::CONFIG;

//         axum_server::tls_rustls::RustlsConfig::from_pem_file(&CONFIG.cert_path, &CONFIG.key_path)
//             .await
//             .expect(&format!(
//                 "Failed to load '{:?}' or '{:?}' pem file!",
//                 CONFIG.cert_path, CONFIG.key_path
//             ))
//     }

//     pub async fn get_http_router() -> axum::Router {
//         axum::Router::new().fallback(h::redirect_to_https)
//     }

//     pub async fn get_https_router() -> axum::Router {
//         use axum::routing::get;

//         axum::Router::new()
//             .route("healthz", get(h::check_app_liveliness))
//             .fallback(h::report_invalid_route)
//     }
// }

#[cfg(test)]
pub mod tests {
    use axum::extract::FromRequest;

    #[derive(Debug, thiserror::Error, axum_thiserror::ErrorStatus)]
    pub enum AppError {
        #[error("Failed to serialize payload parameter into request body! {0}")]
        #[status(axum::http::StatusCode::BAD_REQUEST)]
        FailedSerializePayloadIntoRequestBody(serde_json::Error),

        #[error("Failed to serialize payload parameter from request body! {0}")]
        #[status(axum::http::StatusCode::BAD_REQUEST)]
        FailedSerializePayloadFromRequestBody(serde_json::Error),

        #[error("Failed to build request body from payload parameter! {0}")]
        #[status(axum::http::StatusCode::BAD_REQUEST)]
        FailedBuildRequestBodyFromPayload(axum::http::Error),

        #[error("Failed to extract request body into payload parameter! {0}")]
        #[status(axum::http::StatusCode::BAD_REQUEST)]
        FailedExtractRequestBodyIntoPayload(axum::Error),

        #[error("Failed to serialize payload parameter into response body! {0}")]
        #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
        FailedSerializePayloadIntoResponseBody(serde_json::Error),

        #[error("Failed to serialize payload parameter from response body! {0}")]
        #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
        FailedSerializePayloadFromResponseBody(serde_json::Error),

        #[error("Failed to build response body from payload parameter! {0}")]
        #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
        FailedBuildResponseBodyFromPayload(axum::http::Error),

        #[error("Failed to extract response body into payload parameter! {0}")]
        #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
        FailedExtractResponseBodyIntoPayload(axum::Error),

        #[error("Failed to get router response parameters fro request parameters! {0}")]
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
        pub headers: axum::http::header::HeaderMap,
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
                .map_err(AppError::FailedSerializePayloadIntoRequestBody)?;

            builder
                .body(axum::body::Body::from(body))
                .map_err(AppError::FailedBuildRequestBodyFromPayload)
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
            state: &S,
        ) -> Result<Self, Self::Rejection> {
            let method = req.method().clone();

            let uri = req.uri().clone();

            let path = uri.path().to_string();

            let query = uri.query().unwrap_or("").to_string();

            let version = req.version();

            let headers = req.headers().clone();

            let body = axum::body::to_bytes(req.into_body(), 2 * 1024 * 1024)
                .await
                .map_err(AppError::FailedExtractRequestBodyIntoPayload)?;

            let payload = serde_json::from_slice(&body)
                .map_err(AppError::FailedSerializePayloadFromRequestBody)?;

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
        pub headers: axum::http::header::HeaderMap,
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
                .map_err(AppError::FailedSerializePayloadIntoResponseBody)?;

            builder
                .body(axum::body::Body::from(body))
                .map_err(AppError::FailedBuildResponseBodyFromPayload)
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
                .map_err(AppError::FailedExtractResponseBodyIntoPayload)?;
            let payload = serde_json::from_slice(&body)
                .map_err(AppError::FailedSerializePayloadFromResponseBody)?;

            Ok(ResponseParams {
                version,
                status,
                headers,
                payload,
            })
        }
    }

    pub async fn get_router_response_params_from_request_params(
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
    pub mod config {
        use crate::config::{AppConfig, AppError, CONFIG};

        fn setup_tests() -> (String, String) {
            let learnrust = rcgen::generate_simple_self_signed(vec!["127.0.0.1:3443".into()])
                .expect("Error: Failed to create self-signed certificate!\n");
            let learnrust_crt = learnrust.cert.pem();
            let learnrust_key = learnrust.signing_key.serialize_pem();

            (learnrust_crt, learnrust_key)
        }

        #[test_log::test(tokio::test)]
        async fn test_create_app_config_success() {
            figment::Jail::expect_with(|jail| {
                let (learnrust_crt, learnrust_key) = setup_tests();

                jail.clear_env();

                jail.set_env("HTTP_ADDR", "127.0.0.1:3080");
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt");
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.crt", &learnrust_crt)
                    .expect("Failed to create 'learnrust.crt' file!");
                jail.create_file("learnrust.key", &learnrust_key)
                    .expect("Failed to create 'learnrust.key' file!");

                // cool_asserts::assert_matches!(
                //     AppConfig::new(),
                //     Ok(cfg) => {
                //         pretty_assertions::assert_eq!(cfg.http_addr.to_string(), "127.0.0.1:3080");
                // });

                // Ok(())
                pretty_assertions::assert_eq!(CONFIG.http_addr.to_string(), "127.0.0.1:3080")
            });
        }

        #[test_log::test(tokio::test)]
        async fn test_create_app_config_failure_missing_socket_addr() {
            figment::Jail::expect_with(|jail| {
                let (learnrust_crt, learnrust_key) = setup_tests();

                jail.clear_env();

                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt");
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.crt", &learnrust_crt)
                    .expect("Failed to create 'learnrust.crt' file!");
                jail.create_file("learnrust.key", &learnrust_key)
                    .expect("Failed to create 'learnrust.key' file!");

                cool_asserts::assert_matches!(AppConfig::new(), Err(AppError::FailedFindEnvVar(_)));

                Ok(())
            });
        }

        #[test_log::test(tokio::test)]
        async fn test_create_app_config_failure_invalid_socket_addr() {
            figment::Jail::expect_with(|jail| {
                let (learnrust_crt, learnrust_key) = setup_tests();

                jail.clear_env();

                jail.set_env("HTTP_ADDR", ""); // Invalid SocketAddr
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt");
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.crt", &learnrust_crt)
                    .expect("Failed to create 'learnrust.crt' file!");
                jail.create_file("learnrust.key", &learnrust_key)
                    .expect("Failed to create 'learnrust.key' file!");

                cool_asserts::assert_matches!(
                    AppConfig::new(),
                    Err(AppError::FailedParseSocketAddr(_))
                );

                Ok(())
            });
        }

        #[test_log::test(tokio::test)]
        async fn test_create_app_config_failure_missing_pem_file() {
            figment::Jail::expect_with(|jail| {
                let (_, learnrust_key) = setup_tests();

                jail.clear_env();

                jail.set_env("HTTP_ADDR", "127.0.0.1:3080");
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt"); // Missing PEM File
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.key", &learnrust_key)
                    .expect("Failed to create 'learnrust.key' file!");

                cool_asserts::assert_matches!(
                    AppConfig::new(),
                    Err(AppError::FailedReadPEMFile(_))
                );

                Ok(())
            });
        }

        #[test_log::test(tokio::test)]
        async fn test_create_app_config_failure_invalid_pem_file() {
            figment::Jail::expect_with(|jail| {
                let (_, learnrust_key) = setup_tests();

                jail.clear_env();

                jail.set_env("HTTP_ADDR", "127.0.0.1:3080");
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt");
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.crt", "invalid content")
                    .expect("Failed to create 'learnrust.crt' file!"); // Invalid PEM File
                jail.create_file("learnrust.key", &learnrust_key)
                    .expect("Failed to create 'learnrust.key' file!");

                cool_asserts::assert_matches!(
                    AppConfig::new(),
                    Err(AppError::FailedReadPEMFile(_))
                );

                Ok(())
            });
        }
    }

    // pub mod request {
    //     #[test_log::test(tokio::test)]
    //     async fn test_create_request_from_params_success() {
    //         use axum::http::header::{CONTENT_TYPE, HeaderValue};

    //         let method = axum::http::Method::GET;
    //         let path = "/".to_string();
    //         let query = "key1=value1&key2=value2".to_string();
    //         let version = axum::http::Version::HTTP_11;
    //         let mut headers = axum::http::header::HeaderMap::new();
    //         headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    //         let payload = serde_json::json!({ "key1": "value1", "key2": "value2" });

    //         let expected_params = RequestParams {
    //             method,
    //             path,
    //             query,
    //             version,
    //             headers,
    //             payload,
    //         };

    //         let req = cool_asserts::assert_matches!(axum::extract::Request::try_from(expected_params.clone()), Ok(req) => req);

    //         let actual_params = cool_asserts::assert_matches!(RequestParams::from_request(req, &()).await, Ok(actual_params) => actual_params);

    //         pretty_assertions::assert_eq!(actual_params, expected_params);
    //     }

    //     #[test_log::test(tokio::test)]
    //     async fn test_create_request_from_params_failure_invalid_path() {
    //         use axum::http::header::{CONTENT_TYPE, HeaderValue};

    //         let method = axum::http::Method::GET;
    //         let path = "/invalid path".to_string();
    //         let query = "".to_string();
    //         let version = axum::http::Version::HTTP_11;
    //         let mut headers = axum::http::header::HeaderMap::new();
    //         headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    //         let payload = serde_json::json!({});

    //         let expected_params = RequestParams {
    //             method,
    //             path,
    //             query,
    //             version,
    //             headers,
    //             payload,
    //         };

    //         cool_asserts::assert_matches!(
    //             axum::extract::Request::try_from(expected_params.clone()),
    //             Err(AppError::FailedBuildRequestFromPayload(_))
    //         );
    //     }

    //     #[test_log::test(tokio::test)]
    //     async fn test_create_request_from_params_failure_invalid_query() {
    //         use axum::http::header::{CONTENT_TYPE, HeaderValue};

    //         let method = axum::http::Method::GET;
    //         let path = "/".to_string();
    //         let query = "invalid query".to_string();
    //         let version = axum::http::Version::HTTP_11;
    //         let mut headers = axum::http::header::HeaderMap::new();
    //         headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    //         let payload = serde_json::json!({});

    //         let expected_params = RequestParams {
    //             method,
    //             path,
    //             query,
    //             version,
    //             headers,
    //             payload,
    //         };

    //         cool_asserts::assert_matches!(axum::extract::Request::try_from(expected_params.clone()), Err(AppError::FailedBuildRequestFromPayload(ref err)) => {
    //             pretty_assertions::assert_eq!(err.to_string(), "invalid uri character");
    //         });
    //     }
    // }
    // pub mod response {
    //     use crate::handlers::response::ResponseParams;

    //     #[test_log::test(tokio::test)]
    //     async fn test_create_response_from_params_success() {
    //         let version = axum::http::Version::HTTP_11;

    //         let status = axum::http::StatusCode::OK;

    //         let mut headers = axum::http::header::HeaderMap::new();
    //         headers.insert(
    //             axum::http::header::CONTENT_TYPE,
    //             axum::http::header::HeaderValue::from_static("application/json"),
    //         );

    //         let payload = serde_json::json!({ "key": "value" });

    //         let expected_params = ResponseParams {
    //             version,
    //             status,
    //             headers,
    //             payload,
    //         };

    //         let res = cool_asserts::assert_matches!(axum::response::Response::try_from(expected_params.clone()), Ok(res) => res);

    //         let actual_params = cool_asserts::assert_matches!(ResponseParams::from_response(res).await, Ok(actual_params) => actual_params);

    //         pretty_assertions::assert_eq!(actual_params, expected_params);
    //     }
    // }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    std::sync::LazyLock::force(&config::CONFIG);
}
