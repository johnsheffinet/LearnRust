
/*
add dependencies to Cargo.toml
- cargo add rustls
- cargo add tokio-rustls
*/

use rustls::{Certificate, PrivateKey, ServerConfig};
use std::{fs::File, io::{BufReader, Read}};
use tokio_rustls::TlsAcceptor;

fn get_certs(path: &str) -> Vec<Certificate> {
    // Open the file specified by the path parameter
    let mut reader = BufReader::new(File::open(path).expect("Failed to open {} file", path));
    // Read and return the list of certificates in the file
    rustls_pemfile::certs(&mut reader)
        /*.expect("Failed to read certificates!") */
        .into_iter()
        .map(Certificate)
        .collect().expect("Failed to find certificates!")
}

fn get_key(path: &str) -> PrivateKey {
    // Open the specified file
    let mut reader = BufReader::new(File::open(path).expect("Failed to open {} file!", path));
    // Read a list of private keys in the file
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader).expect("Failed to read private keys!");
    // Return the first private key in the list
    PrivateKey(keys[0].clone().expect("Failed to find private key!"))
}

#[tokio::main]
async fn main() {
    // ...existing code...

    // Load TLS cert and key
    let certs = get_certs("./learnrust.crt");
    let key = get_key("./learnrust.key");

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to configure TLS!");

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3443));
    let listener = TcpListener::bind(addr).await.expect("Failed to bind address!");
    info!("Listening on https://{}", addr);

    loop {
        // Accept a new, TCP connection
        let (stream, client_addr) = listener.accept().await.expect("Failed to accept connection!");
        // Log the accepted connection address
        info!("Accepted connection from {}", client_addr);
        // Clone the acceptor and app for the new task
        // let acceptor = acceptor.clone();
        // let app = app.clone();
        // Spawn a new task to handle the connection
        tokio::spawn(async move {
            // Accept the TLS connection
            let tls_stream = &acceptor.accept(stream).await.expect("Failed to accept TLS connection!");
            // Serve the Axum application over the TLS stream
            axum::serve(tls_stream, &app).await.expect("Failed to serve app!");
        });
    }
}