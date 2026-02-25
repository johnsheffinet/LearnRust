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

    pub static CONFIG: LazyLock<AppConfig> = LazyLock::new(|| { AppConfig::new().unwrap() });
  }
}

#[cfg(test)]
pub mod tests {
  use claim::{assert_ok, assert_err};
  use cool_asserts::assert_matches;
  use pretty_assertions::assert_eq;
  
  pub mod cfg {
    use super::*;
    use crate::handlers::cfg::{AppConfig, AppError, AppResult};
    use figment::Jail;
    
    #[test-log::test(test)]
    fn test_create_app_config_success() {
      Jail::expect_with(|jail| {
        jail.clear_env();
        
        jail.set_env("HTTP_ADDR",  "127.0.0.1:3080");
        jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
        jail.set_env("CERT_PATH",  "learnrust.crt");
        jail.set_env("KEY_PATH",   "learnrust.key");

        jail.create_file("learnrust.crt", "content")?;
        jail.create_file("learnrust.key", "content")?;

        assert_matches!(AppConfig::new(), Ok(AppConfig(val) => {
          assert_eq!(val.http_addr.tostring(), "127.0.0.1:3080");
        }));
      });
    }
    
    #[test-log::test(test)]
    fn test_create_app_config_failure_invalid_socketaddr() {
      Jail::expect_with(|jail| {
        jail.clear_env();
        
        jail.set_env("HTTP_ADDR",  ""); // Invalid SocketAddr
        jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
        jail.set_env("CERT_PATH",  "learnrust.crt");
        jail.set_env("KEY_PATH",   "learnrust.key");

        jail.create_file("learnrust.crt", "content")?;
        jail.create_file("learnrust.key", "content")?;

        assert_matches!(AppConfig::new(), Err(AppError::FailedExtractEnvVar));
      });
    }
    
    #[test-log::test(test)]
    fn test_create_app_config_failure_invalid_pathbuf() {
      Jail::expect_with(|jail| {
        jail.clear_env();
        
        jail.set_env("HTTP_ADDR",  "127.0.0.1:3080");
        jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
        jail.set_env("CERT_PATH",  "\0"); // Invalid PathBuf
        jail.set_env("KEY_PATH",   "learnrust.key");

        jail.create_file("learnrust.crt", "content")?;
        jail.create_file("learnrust.key", "content")?;

        assert_matches!(AppConfig::new(), Err(AppError::FailedExtractEnvVar));
      });      
    }
    
    #[test-log::test(test)]
    fn test_create_app_config_failure_missing_file() {
      Jail::expect_with(|jail| {
        jail.clear_env();
        
        jail.set_env("HTTP_ADDR",  "127.0.0.1:3080");
        jail.set_env("HTTPS_ADDR", "127.0.0.1:3443");
        jail.set_env("CERT_PATH",  "learnrust.crt"); // Missing File
        jail.set_env("KEY_PATH",   "learnrust.key");

        jail.create_file("learnrust.key", "content")?;

        assert_matches!(AppConfig::new(), Err(AppError::FailedValidate(ref errs) => {
          let cert_path_err = assert_some!(
            errs
              .field_errors()
              .get("cert_path")
              .unwrap;
          );
          
          assert_eq!(cert_err[0].code, "FailedFindFile");          
        });
      });

    }
  }
}

#[tokio::main]
async fn main() {
  use std::sync::LazyLock;
  use crate::handlers::cfg::AppConfig;

  tracing_subscriber::fmt::init();
}
