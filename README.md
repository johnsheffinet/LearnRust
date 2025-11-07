# LearnRust

## Setup Environment

- Install Rust with `curl https://sh.rustup.rs --proto "https" --tlsv1.2 --fail --silent --show-error | sh && . "$HOME/.cargo/env"`. Verify Rust is installed with `rustc --version`. 

- Install the following rust tools. 
  - Install *bacon* with `cargo install --locked bacon`. Verify *bacon* is installed with `bacon --version`. 
  - Install *tarpaulin* with `cargo install cargo-tarpaulin`. Verify *tarpaulin* is installed with `cargo tarpaulin --version`. 

- Install the following vscode extensions. 
    - github copilot 
    - rest-client 
    - rust-analyzer 

- Create a *Cargo.toml* file with: 

  ```
  [workspace]
  resolver = "2"

  members = [
      restful
  ]
  ```

- Create a *restful* project with `cargo new add restful`. Verify the project is created with `cd restful && cargo run`. The separate steps for `cargo run` are: 
  1. `cargo check` - tests if the root crate is complete and correct 
  2. `cargo build` - makes the binary for the root crate and links the dependent crates 
  3. `../target/debug/restful` - executes the binary for the root crate 

# Setup Webserver

- add dependencies
```
cargo add axum
cargo add serde --features derive
cargo add serde_json
cargo add tokio --features full
cargo add uuid --features serde,v4
```

# Setup Rest-Client

- create hello_main/.env file 
```
cat > .env<<EOF
HOSTADDR=127.0.0.1
HOSTPORT=3000
EOF
```

- create hello_main.http file
```
cat > hello_main.http<<EOF
@host = {{$dotenv HOSTADDR}}:{{$dotenv HOSTPORT}}
###

# @name create_item
POST http://{{host}}/items HTTP/1.1
content-type: application/json

{
  "name": "item1",
  "value": "This is item 1"
}
###

# @name select_items
GET http://{{host}}/items HTTP/1.1
###

@itemId = {{select_items.response.body.$[0].id}}

# @name update_item
PUT http://{{host}}/items/{{itemId}} HTTP/1.1
content-type: application/json

{
  "name": "item2",
  "value": "This is the updated item 2"
}
###

# @name select_item
GET http://{{host}}/items/{{itemId}} HTTP/1.1
###

# @name delete_item
DELETE http://{{host}}/items/{{itemId}} HTTP/1.1
###

EOF
```

# Setup Validation

- add validator dependency
```
cargo add validator --features derive
```

- import Validate trait & ValidationErrors struct from validator crate
```
use validator::{Validate, ValidationErrors};
```

- add validation_errors_to_map fn
```
fn validation_errors_to_map(errors: ValidationErrors) -> serde_json::Value {...}
```

- annotate name & value fields in CreateItem and UpdateItem structs
```
#[validate(length(min = 1, message = "field is empty"))]
```

# Setup Tracing

- add tracing dependencies
```
cargo add tracing
cargo add tracing-subscriber
```

- import info, debug & warn functions from tracing crate
```
use tracing::{info, debug, warn};
```

- initialize tracing subscriber in main function before starting the server
```
tracing_subscriber::fmt::init();
```

- add tracing spans or events to handlers for debugging and observability
```
tracing::info!("Creating item: {:?}", payload.name);
tracing::debug!(?params, "Filtering items");
tracing::warn!("Item not found: {}", id);
```

# Setup Tests

# Setup TLS

Steps to create a self-signed certificate using OpenSSL. 

1. Openssl

- Verify openssl is installed. 

```
openssl version -a
```

2. Private Key (KEY file)

- Create a private key, which includes the associated public key, in learnrust.key, which is in PEM format. 

```
openssl genrsa -out learnrust.key 4096
```

- Verify a private key is created in learnrust.key by outputting the encoded key. Adding `-noout -text` outputs the decoded key. 

```
openssl rsa -in learnrust.key
```

- Output the encoded, public key. 

```
openssl rsa -in learnrust.key -pubout
```

3. Certificate Signing Request (CSR file)

- Create a certificate signing request in learnrust.csr, which is in PEM format. 

```
openssl req -new -key learnrust.key -subj "/CN=localhost" -out learnrust.csr 
```

- Verify a certificate signing request is created in learnrust.csr. 

```
openssl req -in learnrust.csr -verify
```

- Output the encoded, public key in learnrust.csr. Adding `-noout -text` outputs the decoded key. 

```
openssl req -in learnrust.csr -pubkey
```

4. Certificate (CRT file)

- Create a self-signed certificate in learnrust.crt. 

```
openssl x509 -key learnrust.key -req -in learnrust.csr -days 365 -out learnrust.crt
```

- Verify a self-signed certificate is created in learnrust.crt by outputting the encoded, certificate. Adding `-noout -text` outputs the decoded certificate. 

```
openssl x509 -in learnrust.crt
```

- Output the encoded, public key in learnrust.crt. Adding `-noout -text` outputs the decoded key. 

```
openssl x509 -in learnrust.crt -pubkey
```

5. One Command

- Create private key and certificate signing request in one command. 

```
openssl req -newkey rsa:4096 -nodes -keyout learnrust.key -subj "/CN=localhost" -out learnrust.csr
```

- Create private key and certificate in one command. 

```
openssl req -newkey rsa:4096 -nodes -keyout learnrust.key -subj "/CN=localhost" -x509 -days 365 -out learnrust.crt
```

6. Archive Private Key and Certificate (PFX file)

- Export private key and certificate into learnrust.pfx. 

```
openssl pkcs12 -export -inkey learnrust.key -in learnrust.crt -name "learnrust" -out learnrust.pfx 
```

- Import private key from learnrust.pfx

```
openssl pkcs12 -in learnrust.pfx -nocerts -nodes -out learnrust.key 
```

- Import certificate from learnrust.pfx

```
openssl pkcs12 -in learnrust.pfx -nokeys -clcerts -out learnrust.crt
```

7. CA Trust Store (/usr/local/share/ca-certificates folder)

- Copy the certificate to the local, trust store

```
sudo cp /workspaces/LearnRust/learnrust.crt /usr/local/share/ca-certificates
```

- Update the trust store with the certificate

```
sudo update-ca-certificates
```

- Verify the certificate is in the trust store and in PEM format

```
sudo ls /etc/ssl/certs/ | grep learnrust
echo "Should see 'learnrust.pem'"
```
