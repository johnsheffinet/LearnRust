pub mod handlers {
  pub mod cfg {
    use std::sync::LazyLock;
    
    #[derive(Debug, thiserror::Error)]
    pub enum AppError {
      #[error("Failed to extract environment variables! {0}")]
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
        
        let config = figment::Figment::new()
          .merge(figment::providers::Env::raw()
                .only(&Self::getfields)
                .lowercase(false))
          .extract()?;

        config.validate()?;

        Ok(config)
      }

      #[tracing::instrument(err)]
      fn validate_path(path: &std::path::PathBuf) -> Result<(), validate:ValidationError> {
        if path.exists() {
          Ok(())
        } else {
          Err(validator::ValidationError::new("FailedFindFile"))
        }
      }
    }
    
    pub static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| { AppConfig.new().unwrap() })
  }
}

#[cfg(test)]
pub mod tests {
  pub mod cfg {}
}

#[tokio::main]
async fn main() {}
