pub mod handlers {
  pub mod cfg {
    use std::sync::LazyLock;

    pub static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| { AppConfig::new().unwrap() });
    
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
      #[validate(custom(function = "AppConfig::validate_path", message = "Failed to find certificate file!"))]
      pub cert_path: std::path::PathBuf,
      #[validate(custom(function = "AppConfig::validate_path", message = "Failed to find key file!"))]
      pub key_path: std::path::PathBuf,
    }

    impl AppConfig {
      #[tracing::instrument(err)]
      pub fn new() -> AppResult<Self> {
        use validator::Validate;
        
        let config: AppConfig = figment::Figment::new()
          .merge(figment::providers::Env::raw()
                .only(&Self::get_fields)
                .lowercase(false))
          .extract()?;

        config.validate()?;

        Ok(config)
      }

      #[tracing::instrument(err)]
      pub fn validate_path(path: &std::path::PathBuf) -> Result<(), validator::ValidationError> {
        if path.exists() {
          Ok(())
        } else {
          Err(validator::ValidationError::new("FailedFindFile"))
        }
      }
    }
  }
  pub mod utils {
    use axum::{
      body::{/*to_bytes,*/ Body},
      extract::Request,
      http::{header::HeaderMap, Method, StatusCode, Uri, Version},
      /*response::{IntoResponse, Response},*/
      Json/*, Router,*/
    };
    use serde_json::Value;
    
    #[derive(Debug, thiserror::Error)]
    pub enum AppError {
      #[error("Failed to parse path and query parameters into request uri! {0}")]
      FailedParsePathQueryIntoUri(axum::http::uri::InvalidUri),
      
      #[error("Failed to serialize payload parameter into request body! {0}")]
      FailedSerializePayloadIntoBody(serde_json::Error),
      
      #[error("Failed to build request! {0}")]
      FailedBuildRequest(axum::http::Error),
    }

    pub type AppResult<T> = Result<T, AppError>;

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
    
      #[tracing::instrument(skip(params), err)]
      fn try_from(params: RequestParams) -> Result<Self, Self::Error> {
        let path_and_query = if params.query.is_empty() {
          params.path
        } else {
          format!("{}?{}", params.path, params.query)
        };

        let params_uri = Uri::builder()
          .path_and_query(path_and_query)
          .build()
          .map_err(AppError::FailedParsePathQueryIntoUri)?;

        let params_body = serde_json::to_vec(&params.payload)
          .map_err(AppError::FailedSerializePayloadIntoBody)?;

        let mut builder = Request::builder()
          .method(params.method)
          .uri(params_uri)
          .version(params.version);

        if let Some(headers) = builder.headers_mut() {
          headers.extend(params.headers);
        }

        builder
          .body(Body::from(params_body))
          .map_err(AppError::FailedBuildRequest)
      }
  }

    impl <S> FromRequest<S> for RequestParams 
      where S: Send + Sync {
        type Rejection = AppError;

        #[tracing::instrument(err)]
        pub fn from_request(request: Request) -> Result<Self, Self::Rejection> {
          let params = RequestParams {
            method: ,
            path: ,
            query: ,
            version: ,
            headers: ,
            payload: ,
          }

          Ok(params)
        }
      }

    pub struct ResponseParams {
      version: Version,
      status: StatusCode,
      headers: HeaderMap,
      payload: Json<Value>,
    }

    impl TryFrom<ResponseParams> for Response {}

    impl FromResponse<Response> for ResponseParams {}
  }
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
        
        jail.set_env("HTTP_ADDR",  "127.0.0.1:3080");
        jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
        jail.set_env("CERT_PATH",  "learnrust.crt");
        jail.set_env("KEY_PATH",   "learnrust.key");

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
        
        jail.set_env("HTTP_ADDR",  ""); // Invalid SocketAddr
        jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
        jail.set_env("CERT_PATH",  "learnrust.crt");
        jail.set_env("KEY_PATH",   "learnrust.key");

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
        
        jail.set_env("HTTP_ADDR",  "127.0.0.1:3080");
        jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
        jail.set_env("CERT_PATH",  "learnrust.crt"); // Missing File
        jail.set_env("KEY_PATH",   "learnrust.key");

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
}

#[tokio::main]
async fn main() {
  tracing_subscriber::fmt::init();

  std::sync::LazyLock::force(&handlers::cfg::CONFIG);
}
