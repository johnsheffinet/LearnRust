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
        use axum::{
            body::Body,
            extract::{FromRequest, Json, Request},
            http::{Method, StatusCode, Uri, Version, header::HeaderMap},
        };
        use serde_json::Value;

        #[derive(Debug, thiserror::Error, axum_thiserror::ErrorStatus)]
        pub enum AppError {
            #[error("Failed to build request uri from path and query parameters! {0}")]
            #[status(StatusCode::BAD_REQUEST)]
            FailedBuildUri(#[from] axum::http::uri::InvalidUri),

            #[error("Failed to serialize payload parameter into request body! {0}")]
            #[status(StatusCode::BAD_REQUEST)]
            FailedSerializePayload(#[from] serde_json::Error),

            #[error("Failed to build request! {0}")]
            #[status(StatusCode::BAD_REQUEST)]
            FailedBuildRequest(#[from] axum::http::Error),

            #[error("Failed to extract payload parameter from request body! {0}")]
            #[status(StatusCode::BAD_REQUEST)]
            FailedExtractPayload(#[from] axum::extract::rejection::JsonRejection),
        }

        pub type AppResult<T> = Result<T, AppError>;

        #[derive(Debug, Clone)]
        pub struct RequestParams {
            pub method: Method,
            pub path: String,
            pub query: String,
            pub version: Version,
            pub headers: HeaderMap,
            pub payload: Value,
        }

        impl TryFrom<RequestParams> for Request {
            type Error = AppError;

            #[tracing::instrument(skip_all, err)]
            fn try_from(params: RequestParams) -> Result<Self, Self::Error> {
                let path_and_query = if params.query.is_empty() {
                    params.path
                } else {
                    format!("{}?{}", params.path, params.query)
                };

                let params_uri = Uri::builder().path_and_query(path_and_query).build()?; // FailedBuildUri(#[from] axum::http::uri::InvalidUri)

                let mut builder = Request::builder()
                    .method(params.method)
                    .uri(params_uri)
                    .version(params.version);

                if let Some(headers) = builder.headers_mut() {
                    headers.extend(params.headers);
                }

                let bytes = serde_json::to_vec(&params.payload)?; // FailedSerializePayload(#[from] serde_json::Error)

                builder
                    .body(Body::from(bytes))
                    .map_err(AppError::FailedBuildRequest) // FailedBuildRequest(#[from] axum::http::Error)                
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
                let Json(payload) = Json::<Value>::from_request(req, state).await?; // FailedSerializePayload(#[from] axum::extract::rejection::JsonRejection) 

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
        use axum::{
            body::{Body, to_bytes},
            http::{StatusCode, Version, header::HeaderMap},
            response::Response,
        };
        use serde_json::Value;

        #[derive(Debug, thiserror::Error)]
        pub enum AppError {
            #[error("Failed to serialize payload parameter into! {0}")]
            FailedSerializePayload(#[from] serde_json::Error),

            #[error("Failed to build response! {0}")]
            FailedBuildResponse(#[from] axum::http::Error),

            #[error("Failed to extract bytes from response body! {0}")]
            FailedExtractBytes(#[from] axum::Error),
        }

        pub type AppResult<T> = Result<T, AppError>;

        #[derive(Debug, Clone)]
        pub struct ResponseParams {
            pub version: Version,
            pub status: StatusCode,
            pub headers: HeaderMap,
            pub payload: Value,
        }

        impl TryFrom<ResponseParams> for Response {
            type Error = AppError;

            #[tracing::instrument(skip_all, err)]
            fn try_from(params: ResponseParams) -> Result<Self, Self::Error> {
                let mut builder = Response::builder()
                    .version(params.version)
                    .status(params.status);

                if let Some(headers) = builder.headers_mut() {
                    headers.extend(params.headers);
                }

                let bytes = serde_json::to_vec(&params.payload)?; // FailedSerializePayload(#[from] serde_json::Error)

                builder
                    .body(Body::from(bytes))
                    .map_err(AppError::FailedBuildResponse) // FailedBuildResponse(#[from] axum::http::Error)                
            }
        }

        impl ResponseParams {
            #[tracing::instrument(skip_all, err)]
            pub async fn from_response(res: Response) -> AppResult<Self> {
                let version = res.version();
                let status = res.status();
                let headers = res.headers().clone();
                let bytes = to_bytes(res.into_body(), 2 * 1024 * 1024).await?; // FailedExtractBytes(#[from] axum::Error)
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
    use claims::assert_some;
    use cool_asserts::assert_matches;

    pub mod cfg {
        use super::*;
        use crate::handlers::cfg::{AppConfig, AppError};
        use figment::Jail;
        use pretty_assertions::assert_eq;

        #[test_log::test(test)]
        fn test_create_app_config_success() {
            Jail::expect_with(|jail| {
                jail.clear_env();

                jail.set_env("HTTP_ADDR", "127.0.0.1:3080");
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt");
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.crt", "content")?;
                jail.create_file("learnrust.key", "content")?;

                assert_matches!(AppConfig::new(), Ok(val) => {
                  assert_eq!(val.http_addr.to_string(), "127.0.0.1:3080");
                });

                Ok(())
            });
        }

        #[test_log::test(test)]
        fn test_create_app_config_failure_invalid_socketaddr() {
            Jail::expect_with(|jail| {
                jail.clear_env();

                jail.set_env("HTTP_ADDR", ""); // Invalid SocketAddr
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt");
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.crt", "content")?;
                jail.create_file("learnrust.key", "content")?;

                assert_matches!(AppConfig::new(), Err(AppError::FailedExtractEnvVar(_)));

                Ok(())
            });
        }

        #[test_log::test(test)]
        fn test_create_app_config_failure_missing_file() {
            Jail::expect_with(|jail| {
                jail.clear_env();

                jail.set_env("HTTP_ADDR", "127.0.0.1:3080");
                jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
                jail.set_env("CERT_PATH", "learnrust.crt"); // Missing File
                jail.set_env("KEY_PATH", "learnrust.key");

                jail.create_file("learnrust.key", "content")?;

                assert_matches!(AppConfig::new(), Err(AppError::FailedValidate(ref errs)) => {
                  let field_errs = errs.field_errors();

                  let cert_path_err = assert_some!(
                    field_errs.get("cert_path"));

                  assert_eq!(cert_path_err[0].code, "FailedFindFile");
                });

                Ok(())
            });
        }
    }
    pub mod request {
        use super::*;
        use crate::handlers::request::{AppError, AppResult, RequestParams};
        use pretty_assertions::assert_eq;

        async fn test_create_request_from_params_success() {}
        async fn test_create_request_from_params_failure_invalid_path() {}
        async fn test_create_request_from_params_failure_invalid_query() {}
        async fn test_create_request_from_params_failure_invalid_payload() {}
        async fn test_create_params_from_request_success() {}
        async fn test_create_params_from_request_failure_invalid_body() {}
    }
    pub mod response {
        use super::*;
        use crate::handlers::response::{AppError, AppResult, ResponseParams};
        use pretty_assertions::assert_eq;
        
    }
    pub mod router {
        use super::*;
        use crate::handlers::router;
        use pretty_assertions::assert_eq;
        
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    std::sync::LazyLock::force(&handlers::cfg::CONFIG);
}
