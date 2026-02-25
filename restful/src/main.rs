pub mod handlers {
  pub mod cfg {
    #[derive(Debug, thiserror::Error)]
    pub enum AppError {
      #[error("Failed to extract environment variables!")]
      FailedExtractEnvVar(#[from] figment::Error),
      
      #[error("Failed to validate application configuration!")]
      FailedValidateAppCfg(#[from] validator::ValidationError),
      
    }

    pub type AppResult<T> = Result<T, AppError>;

    #[derive(Debug, serde::Deserialize, get_fields::GetFields, validator::Validate)]
    pub struct AppConfig {
      pub http_addr: std::net::SocketAddr;
      pub https_addr: std::net::SocketAddr;
      #[validate(custom(function = "AppConfig::validate_path", message = "Failed to find certificate file!"))]
      pub cert_path: std::path::PathBuf;
      #[validate(custom(function = "AppConfig::validate_path", message = "Failed to find key file!"))]
      pub key_path: std::path::PathBuf;
    }

    impl AppConfig {
      #[tracing::instrument(err)]
      fn new() -> AppResult<Self> {
        let config = Figment::new()
          .merge(figment::providers::Env::raw()
                .only(Self::getfields)
                .lowercase(false))
          .extract()?

        config.validate()?

        Ok(config)
      }

      #[tracing::instrument(err)]
      fn validate_path(path: std::path::PathBuf) -> Result<(), validate:ValidationError> {
        
      }
    }
  }
}

#[cfg(test)]
pub mod tests {
  pub mod cfg {}
}

#[tokio::main]
async fn main() {}
