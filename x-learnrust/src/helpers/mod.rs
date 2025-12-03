pub mod tls;
pub mod utils {
    pub fn read_env_var(key: &str) -> String {
        std::env::var(key)
            .expect(&format!(
                "Failed to read {} environment variable!", 
                key,
            )
        )
    }
}