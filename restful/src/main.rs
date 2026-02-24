pub mod handlers {
  pub mod cfg {
    #[derive(Debug, serde::Deserialize, thiserror::Error)]
    pub enum AppError {
      #[error("Failed to ...!")]
      Failed(#[from] ),
      
    }

    pub type AppResult<T> = Result<T, AppError>;

    #[derive()]
    pub struct AppConfig {
      pub http_addr: std::net::SocketAddr;
      pub https_addr: std::net::SocketAddr;
      pub cert_path: std::PathBuf;
      pub key_path: std::PathBuf;
    }

    impl AppConfig {}
  }
}

#[cfg(test)]
pub mod tests {
  pub mod cfg {}
}

async fn main() {}
