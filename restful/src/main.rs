pub mod handlers {
    pub mod cfg {
        use std::sync::LazyLock;

        pub static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| AppConfig::new().unwrap());

        #[derive(Debug, thiserror::Error)]
        pub enum AppError {
            #[error("Failed to extract environment variable! {0}")]
            FailedExtractEnvVar(#[from] figment::Error),

            #[error("{0}")]
            FailedValidate(#[from] validator::ValidationErrors),
        }

        pub type AppResult<T> = Result<T, AppError>;

        #[derive(Debug, serde::Deserialize, get_fields::GetFields, validator::Validate)]
        #[serde(rename_all = "UPPERCASE")]
        #[get_fields(rename_all = "UPPERCASE")]
        pub struct AppConfig {
            pub http_addr: std::net::SocketAddr,
            pub https_addr: std::net::SocketAddr,
            #[validate(custom(
                function = "AppConfig::validate_path",
                message = "Failed to find certificate file!"
            ))]
            pub cert_path: std::path::PathBuf,
            #[validate(custom(
                function = "AppConfig::validate_path",
                message = "Failed to find key file!"
            ))]
            pub key_path: std::path::PathBuf,
        }

        impl AppConfig {
            #[tracing::instrument(err)]
            pub fn new() -> AppResult<Self> {
                use validator::Validate;

                let config: AppConfig = figment::Figment::new()
                    .merge(
                        figment::providers::Env::raw()
                            .only(&Self::get_fields)
                            .lowercase(false),
                    )
                    .extract()?;

                config.validate()?;

                Ok(config)
            }

            #[tracing::instrument(err)]
            pub fn validate_path(
                path: &std::path::PathBuf,
            ) -> Result<(), validator::ValidationError> {
                if path.exists() {
                    Ok(())
                } else {
                    Err(validator::ValidationError::new("FailedFindFile"))
                }
            }
        }
    }
    pub mod request {
        use axum::extract::{FromRequest, Json, Request};

        #[derive(Debug, thiserror::Error, axum_thiserror::ErrorStatus)]
        pub enum AppError {
            #[error("Failed to serialize payload parameter into request body! {0}")]
            #[status(axum::http::StatusCode::BAD_REQUEST)]
            FailedSerializePayload(#[from] serde_json::Error),

            #[error("Failed to build request! {0}")]
            #[status(axum::http::StatusCode::BAD_REQUEST)]
            FailedBuildRequest(#[from] axum::http::Error),

            #[error("Failed to extract payload parameter from request body! {0}")]
            #[status(axum::http::StatusCode::BAD_REQUEST)]
            FailedExtractPayload(#[from] axum::extract::rejection::JsonRejection),
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

        impl TryFrom<RequestParams> for Request {
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

                let bytes = serde_json::to_vec(&params.payload)?; // FailedSerializePayload(#[from] serde_json::Error)

                builder
                    .body(axum::body::Body::from(bytes))
                    .map_err(AppError::FailedBuildRequest)
            }
        }

        impl<S> FromRequest<S> for RequestParams
        where
            S: Send + Sync,
        {
            type Rejection = AppError;

            #[tracing::instrument(skip_all, err)]
            async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
                let method = req.method().clone();
                let uri = req.uri().clone();
                let path = uri.path().to_string();
                let query = uri.query().unwrap_or("").to_string();
                let version = req.version();
                let headers = req.headers().clone();
                let Json(payload) = Json::<serde_json::Value>::from_request(req, state).await?; // FailedSerializePayload(#[from] axum::extract::rejection::JsonRejection) 

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
    }
    pub mod response {
        #[derive(Debug, thiserror::Error, axum_thiserror::ErrorStatus)]
        pub enum AppError {
            #[error("Failed to serialize payload parameter into! {0}")]
            #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
            FailedSerializePayload(#[from] serde_json::Error),

            #[error("Failed to build response! {0}")]
            #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
            FailedBuildResponse(#[from] axum::http::Error),

            #[error("Failed to extract bytes from response body! {0}")]
            #[status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)]
            FailedExtractBytes(#[from] axum::Error),
        }

        pub type AppResult<T> = Result<T, AppError>;

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

                let bytes = serde_json::to_vec(&params.payload)?; // FailedSerializePayload(#[from] serde_json::Error)

                builder
                    .body(axum::body::Body::from(bytes))
                    .map_err(AppError::FailedBuildResponse) // FailedBuildResponse(#[from] axum::http::Error)                
            }
        }

        impl ResponseParams {
            #[tracing::instrument(skip_all, err)]
            pub async fn from_response(res: axum::response::Response) -> AppResult<Self> {
                let version = res.version();
                let status = res.status();
                let headers = res.headers().clone();
                let bytes = axum::body::to_bytes(res.into_body(), 2 * 1024 * 1024).await?; // FailedExtractBytes(#[from] axum::Error)
                let payload = serde_json::from_slice(&bytes)?; // FailedSerializePayload(#[from] serde_json::Error)

                Ok(ResponseParams {
                    version,
                    status,
                    headers,
                    payload,
                })
            }
        }
    }
    pub mod utils {}
}

#[cfg(test)]
pub mod tests {
    pub mod cfg {
        use crate::handlers::cfg::{AppConfig, AppError};

        #[test_log::test(test)]
        fn test_create_app_config_success() {
            figment::Jail::expect_with(|jail| {
                jail.clear_env();

                jail.set_env("HTTP_ADDR", "127.0.0.1:3080");
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt");
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.crt", "content")?;
                jail.create_file("learnrust.key", "content")?;

                cool_asserts::assert_matches!(AppConfig::new(), Ok(val) => {
                  pretty_assertions::assert_eq!(val.http_addr.to_string(), "127.0.0.1:3080");
                });

                Ok(())
            });
        }

        #[test_log::test(test)]
        fn test_create_app_config_failure_invalid_socketaddr() {
            figment::Jail::expect_with(|jail| {
                jail.clear_env();

                jail.set_env("HTTP_ADDR", ""); // Invalid SocketAddr
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt");
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.crt", "content")?;
                jail.create_file("learnrust.key", "content")?;

                cool_asserts::assert_matches!(
                    AppConfig::new(),
                    Err(AppError::FailedExtractEnvVar(_))
                );

                Ok(())
            });
        }

        #[test_log::test(test)]
        fn test_create_app_config_failure_missing_file() {
            figment::Jail::expect_with(|jail| {
                jail.clear_env();

                jail.set_env("HTTP_ADDR", "127.0.0.1:3080");
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt"); // Missing File
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.key", "content")?;

                cool_asserts::assert_matches!(AppConfig::new(), Err(AppError::FailedValidate(ref errs)) => {
                  let field_errs = errs.field_errors();

                  let cert_path_err = claims::assert_some!(
                    field_errs.get("cert_path"));

                  pretty_assertions::assert_eq!(cert_path_err[0].code, "FailedFindFile");
                });

                Ok(())
            });
        }
    }
    pub mod request {
        use crate::handlers::request::{AppError, RequestParams};
        use axum::extract::{FromRequest, Request};

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

            let req = Request::try_from(expected_params.clone())
                .expect("Failed to create request from request parameters!");

            let actual_params = RequestParams::from_request(req, &())
                .await
                .expect("Failed to create request parameters from request!");

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

            let result = Request::try_from(expected_params.clone());

            cool_asserts::assert_matches!(result, Err(AppError::FailedBuildRequest()));
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

            let result = Request::try_from(expected_params.clone());

            cool_asserts::assert_matches!(result, Err(AppError::FailedBuildRequest()));            
        }

        #[test_log::test(tokio::test)]
        async fn test_create_request_from_params_failure_invalid_payload() {
            use axum::http::header::{CONTENT_TYPE, HeaderValue};

            let method = axum::http::Method::GET;
            let path = "/invalid path".to_string();
            let query = "".to_string();
            let version = axum::http::Version::HTTP_11;
            let mut headers = axum::http::header::HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let payload = serde_json::json!({ "invalid payload": f64::NAN });

            let expected_params = RequestParams {
                method,
                path,
                query,
                version,
                headers,
                payload,
            };

            let result = Request::try_from(expected_params.clone());

            cool_asserts::assert_matches!(result, Err(AppError::FailedSerializePayload()));            
        }

        #[test_log::test(tokio::test)]
        async fn test_create_params_from_request_success() {}

        #[test_log::test(tokio::test)]
        async fn test_create_params_from_request_failure_invalid_body() {}
    }
    pub mod response {
        use crate::handlers::response::ResponseParams;

        #[test_log::test(tokio::test)]
        async fn test_create_response_from_params_success() {}

        #[test_log::test(tokio::test)]
        async fn test_create_response_from_params_failure_invalid_payload() {}

        #[test_log::test(tokio::test)]
        async fn test_create_params_from_response_success() {}

        #[test_log::test(tokio::test)]
        async fn test_create_params_from_response_failure_invalid_body() {}
    }
    pub mod router {
        // use super::*;
        // use crate::handlers::router;
        // use pretty_assertions::assert_eq;
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    std::sync::LazyLock::force(&handlers::cfg::CONFIG);
}
