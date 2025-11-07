use crate::helpers::tls;

#[tokio::main]
async fn main() {

    let HTTP_ADDR: String = helpers::read_env_var("HTTP_ADDR");

    let http_server_task = tokio::spawn(
        tls::serve_http_app(
            "HTTP_ADDR"
        )
    );
    
    let https_server_task = tokio::spawn(
        tls::serve_https_app(
            "HTTPS_ADDR", 
            "CERT_PATH", 
            "KEY_PATH",
        )
    );

    let _ = tokio::join!(http_server_task, https_server_task);
}

pub mod helpers {
    use std::{env, f32::consts::E};

    pub fn read_env_var(key: &str) -> String {
        env::var(key)
            .expect(&format!(
                "Failed to read {} environment variable!", 
                key,
            )
        )
    }
    pub mod tls {
        use axum::{http::Uri, response::Redirect, routing::get, Router};
        use axum_server::tls_rustls::RustlsConfig;
        use crate::helpers;
        use std::net::SocketAddr;

        pub async fn serve_https_app(
            https_addr_env_var: &str,
            cert_path_env_var: &str,
            key_path_env_var: &str,
        ) {
            let https_addr= helpers::read_env_var(https_addr_env_var).await;
            let cert_path = helpers::read_env_var(cert_path_env_var).await;
            let key_path = helpers::read_env_var(key_path_env_var).await;

            let addr: SocketAddr = https_addr
                .parse()
                .expect(&format!(
                        "Failed to parse {} into socket address!", 
                        https_addr,
                    )
                );

            let config:RustlsConfig = RustlsConfig::from_pem_file(
                    &cert_path, 
                    &key_path,
                )
                .await
                .expect(&format!(
                        "Failed to read {} or {} files!",
                        &cert_path,
                        &key_path,
                    )
                );

            let app: Router = Router::new()
                .route("/", get(|| async {"Hello from https app.\n"}));

            axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service())
                .await
                .expect(&format!(
                        "Failed to serve https app on {}",
                        addr,
                    )
                );
        }

        pub async fn serve_http_app(http_addr_env_var: &str) {
            let http_addr = helpers::read_env_var(http_addr_env_var).await;

            let addr = http_addr
                .parse()
                .expect(&format!(
                        "Failed to parse {}={} into socket address!",
                        http_addr_env_var,
                        http_addr,
                    )
                );

            let app = Router::new()
                .route("/", get(redirect_to_https));

            axum_server::bind(addr)
                .serve(app.into_make_service())
                .await
                .expect(&format!("Failed to serve http app on {}!", addr));
        }

        async fn redirect_to_https(uri: Uri) -> Redirect {
            let https_uri = format!("https://127.0.0.1:3443{}", uri.path());
            Redirect::temporary(&https_uri)
        }
    }
}
