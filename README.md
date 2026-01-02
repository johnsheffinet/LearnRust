# LearnRust

## Setup Environment

- Install Rust with `curl https://sh.rustup.rs --proto "https" --tlsv1.2 --fail --silent --show-error | sh && . "$HOME/.cargo/env"`. Verify Rust is installed with `rustc --version`. 

- Install the following rust tools. 
  - Install *bacon* with `cargo install --locked bacon`. Verify *bacon* is installed with `bacon --version`. **bacon** is a popular command-line tool that acts as a background code checker and task runner. It automatically monitors your source files for changes and runs specified cargo commands, such as check or test, providing immediate feedback on errors and warnings without manual input. 
  - Install *tarpaulin* with `cargo install cargo-tarpaulin`. Verify *tarpaulin* is installed with `cargo-tarpaulin --version`. **tarpaulin** is a code coverage reporting tool that helps developers measure how much of their code is being executed by their test suites. 

- Install the following vscode extensions. 
    - github copilot: **gitHub copilot** is an AI-powered coding assistant that acts as a "pair programmer" to help developers write code faster and more efficiently. Developed by GitHub and OpenAI, it uses a large language model (specifically, the Codex model, a descendant of GPT-3) to provide contextual suggestions and automate various development tasks directly within a developer's integrated development environment (IDE).
    - rest-client: **rest client** is a popular extension that allows you to send HTTP, GraphQL, and SOAP requests and view the responses directly within the editor. This eliminates the need to switch to an external tool like Postman or cURL for testing APIs, streamlining the development workflow.
    - rust-analyzer: **rust-analyzer** is the official and recommended extension for Rust development in VS Code, providing a comprehensive set of IDE features by implementing the Language Server Protocol (LSP). It deeply understands your Rust code, offering powerful tools that go beyond simple text editing. 

- Create a *Cargo.toml* file with: 

  ```
  [workspace]
  resolver = "2"

  members = [
      "restful"
  ]
  ```

- Create a *restful* project with `cargo new restful`. Verify the project is created with `cd restful && cargo run`. The separate steps for `cargo run` are: 
  1. `cargo check` - tests if the root crate is complete and correct 
  2. `cargo build` - makes the binary for the root crate and links the dependent crates 
  3. `../target/debug/restful` - executes the binary for the root crate 

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
```
openssl req -newkey rsa:4096 -nodes -keyout learnrust.key -addext "subjectAltName = IP:127.0.0.1" -x509 -days 365 -out learnrust.crt
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
