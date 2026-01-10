use once_cell::sync::Lazy;
use crate::handlers::utils::get_env_var;

const HTTP_ADDR: Lazy<String> = Lazy::new(|| {get_env_var("HTTP_ADDR".to_string())});
const HTTPS_ADDR: Lazy<String> = Lazy::new(|| {get_env_var("HTTPS_ADDR".to_string())});
const CERT_PATH: Lazy<String> = Lazy::new(|| {get_env_var("CERT_PATH".to_string())});
const KEY_PATH: Lazy<String> = Lazy::new(|| {get_env_var("KEY_PATH".to_string())});
        

#[tokio::main]
async fn main() {
    use crate::handlers::tls;

    let serve_app_over_https_task = tokio::spawn(axum_server::bind_rustls(get_socket_addr(HTTPS_ADDR.to_string()), get_rustls_config(CERT_PATH.to_string(), KEY_PATH.to_string()))
        .serve(get_https_router().into_make_service())
        .await
        .unwrap());

    let redirect_req_to_https_task = tokio::spawn(axum_server::bind(get_socket_addr(HTTP_ADDR.to_string()))
        .serve(get_http_router(HTTPS_ADDR.to_string()).into_make_service())
        .await
        .unwrap());
    
    let _ = tokio::join!(serve_app_over_https_task, redirect_req_to_https_task);
}

pub(crate) mod handlers {
    pub mod utils {
        pub fn get_env_var(key: String) -> String {
            std::env::var(key.clone())
                .expect(&format!("Failed to get '{}' environment variable!", key))
        }

        // use http::{Method, Request, Uri, Version, HeaderValue};
        // use http::header::{CONTENT_TYPE, AUTHORIZATION};
        
        // fn create_internal_request() -> Request<String> {
        //     // 1. Define the Method
        //     let method = Method::POST;
        
        //     // 2. Define the URI
        //     let uri: Uri = "/api/v1/data".parse().expect("Invalid URI");
        
        //     // 3. Define Headers
        //     let mut headers = http::HeaderMap::new();
        //     headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        //     headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer test_token"));
        
        //     // 4. Define the Body
        //     let body = r#"{"key": "value", "count": 42}"#.to_string();
        
        //     // 5. Use the Request::builder() to assemble the components
        //     let request = Request::builder()
        //         .method(method)
        //         .uri(uri)
        //         .version(Version::HTTP_11) // Optional: specify HTTP version
        //         .headers(headers)
        //         .body(body)
        //         .expect("Failed to build request");
        
        //     println!("--- Constructed Request ---");
        //     println!("Method: {}", request.method());
        //     println!("URI: {}", request.uri());
        //     println!("Headers: {:#?}", request.headers());
        //     println!("Body: {}", request.body());
        //     println!("---------------------------");
        
        //     request
}

fn main() {
    create_internal_request();
}

    }
    pub mod tls {
        use axum::http::StatusCode;

        pub async fn get_socket_addr(addr: String) -> std::net::SocketAddr {
            addr
                .parse()
                .expect(&format!("Failed to parse '{}' address!", addr))                    
        }

        pub async fn get_rustls_config(cert_path: String, key_path: String) -> axum_server::tls_rustls::RustlsConfig {
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path.clone(), key_path.clone())
                .await
                .expect(&format!("Failed to load '{}' or '{}' pem files!", cert_path, key_path))                
        }

        pub async fn get_https_router() -> axum::Router {
            axum::Router::new()
                .route("/healthz", axum::routing::get(|| async {(StatusCode::OK, "App is healthy.")}))
                .fallback(|uri: axum::http::Uri| async move {(StatusCode::NOT_FOUND, format!("'{}' route is invalid!", uri.path()))})            
        }
        
        pub async fn get_http_router(https_addr: String) -> axum::Router {
            axum::Router::new()
                .fallback(|uri: axum::http::Uri,| async move {
                    axum::response::Redirect::temporary(&format!("https://{}{}", https_addr, uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/")))
                })            
        }
        
        // pub async fn serve_app_over_https(https_addr: String, cert_path: String, key_path: String) {
        //     let addr = get_socket_addr(https_addr).await;
            
        //     let config = get_rustls_config(cert_path.clone(), key_path.clone()).await;

        //     let router = get_https_router().await;
            
        //     axum_server::bind_rustls(addr, config)
        //         .serve(router.into_make_service())
        //         .await
        //         .unwrap();            
        // }

        // pub async fn redirect_req_to_https(http_addr: String, https_addr: String) {
        //     let addr = get_socket_addr(http_addr).await;
            
        //     let router = get_http_router(https_addr).await;
            
        //     axum_server::bind(addr)
        //         .serve(router.into_make_service())
        //         .await
        //         .unwrap();
        // }
    }
}

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    const INVALID_VALUE: Lazy<String> = Lazy::new(|| {" ".to_string()});

    mod utils_tests {
        use super::*;
        use crate::{HTTP_ADDR, handlers::utils};
        
        #[tokio::test]
        #[should_panic(expected = "Failed to get ' ' environment variable!")]
        async fn test_get_env_var_failed_to_get_environment_variable() {
            let _ = utils::get_env_var(" ".to_string());
        }
    
        #[tokio::test]
        async fn test_get_env_var_success() {
            let result = utils::get_env_var("HTTP_ADDR".to_string());
            assert_eq!(result, *HTTP_ADDR);
        }
    }
    mod tls_tests {
        use super::*;
        use crate::{HTTP_ADDR, HTTPS_ADDR, CERT_PATH, KEY_PATH, handlers::tls};
        
            #[tokio::test]
            #[should_panic(expected = "Failed to parse ' ' address!")]
            async fn test_get_socket_addr_failed_to_parse_address() {
                let _ = tls::get_socket_addr(" ".to_string());    
            }
            
            #[tokio::test]
            async fn test_get_addr_success() {
                let result = tls::get_socket_addr(HTTPS_ADDR.to_string()).await;
                assert!(result.is_ipv4());    
            }    

            #[tokio::test]
            #[should_panic(expected = "Failed to load ' ' or '/workspaces/LearnRust/learnrust.key' pem files!")]
            async fn test_get_rustls_config_failed_to_load_cert_pem_file() {
                let _ = axum_server::tls_rustls::RustlsConfig::from_pem_file(" ".to_string(), KEY_PATH.clone());
            }
            
            #[tokio::test]
            #[should_panic(expected = "Failed to load '/workspaces/LearnRust/learnrust.crt' or ' ' pem files!")]
            async fn test_get_rustls_config_failed_to_load_key_pem_file() {
                let _ = axum_server::tls_rustls::RustlsConfig::from_pem_file(CERT_PATH.clone(), " ".to_string());
            }
            
            #[tokio::test]
            async fn test_get_rustls_config_success() {
                let _ = axum_server::tls_rustls::RustlsConfig::from_pem_file(CERT_PATH.clone(), KEY_PATH.clone());
            }
            
            #[tokio::test]
            async fn test_get_https_router_ok_app_is_healthy() {
                let router = tls::get_https_router().await;
                let response = router
                    .oneshot(axum::http::Request::get("/healthz")
                                .header("Content-Type", "text/plain; charset=utf-8")
                    .unwrap());
                assert_eq!(response.status(), StatusCode::OK);
                let body = body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert_eq!(body, "App is healthy.");
            }
            
            #[tokio::test]
            async fn test_get_https_router_not_found_route_is_invalid() {
                let router = tls::get_https_router().await;
                let response = router
                    .oneshot(Request::get("/")
                                .header("Content-Type", "text/plain; charset=utf-8")
                                .unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
                let body = body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert_eq!(body, "'/' route is invalid!");
            }
            
            #[tokio::test]
            async fn test_get_http_router_temporary_redirect() {
                let router = tls::get_https_router().await;
                let response = router
                    .oneshot(Request::get("/")
                                .header("Content-Type", "text/plain; charset=utf-8")
                                .unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
                let body = body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert_eq!(body, "'/' route is invalid!");
            }
    }
}
//     mod trc {
//         use axum::{
//             body::{Body, Bytes},
//             http::{Request, Response, StatusCode, HeaderMap, Method, Version},
//             middleware::{self, Next},
//             routing::get,
//             Router,
//         };
//         use std::net::SocketAddr;
//         use futures_util::future::BoxFuture;
//         use tower::{Service, Layer};
//         use std::task::{Context, Poll};
//         use tracing::{info, Level};
//         use tracing_subscriber::{fmt, prelude::*, filter::LevelFilter};

//         // A helper function to buffer and print the body.
//         // This is necessary because the body is a stream and must be consumed or re-wrapped.
//         async fn buffer_and_print(label: &str, body: Body) -> Result<Bytes, StatusCode> {
//             let bytes = hyper::body::to_bytes(body)
//                 .await
//                 .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

//             if !bytes.is_empty() {
//                 if let Ok(s) = std::str::from_utf8(&bytes) {
//                     info!("{} body: {}", label, s);
//                 } else {
//                     info!("{} body (binary): {:?}", label, bytes);
//                 }
//             } else {
//                 info!("{} body: (empty)", label);
//             }

//             Ok(bytes)
//         }

//         // The core middleware function
//         async fn logging_middleware(
//             req: Request<Body>,
//             next: Next<Body>,
//         ) -> Result<Response<Body>, (StatusCode, String)> {
//             let (req_parts, req_body) = req.into_parts();

//             // Log Request details
//             info!("Incoming Request:");
//             info!("- Method: {:?}", req_parts.method);
//             info!("- URI: {:?}", req_parts.uri);
//             info!("- Version: {:?}", req_parts.version);
//             info!("- Headers: {:#?}", req_parts.headers);

//             // Buffer and log the request body, then create a new request with the buffered body
//             let req_bytes = buffer_and_print("Request", req_body).await.map_err(|e| (e, "Bad request body".to_string()))?;
//             let req = Request::from_parts(req_parts, Body::from(req_bytes));

//             // Process the request
//             let res = next.run(req).await;

//             let (res_parts, res_body) = res.into_parts();

//             // Log Response details
//             info!("Outgoing Response:");
//             info!("- Version: {:?}", res_parts.version);
//             info!("- Status: {:?}", res_parts.status);
//             info!("- Headers: {:#?}", res_parts.headers);

//             // Buffer and log the response body, then create a new response with the buffered body
//             let res_bytes = buffer_and_print("Response", res_body).await.map_err(|e| (e, "Bad response body".to_string()))?;
//             let res = Response::from_parts(res_parts, Body::from(res_bytes));

//             Ok(res)
//         }

//         // A simple handler
//         async fn hello_world() -> &'static str {
//             "Hello, World!"
//         }

//         #[tokio::main]
//         async fn main() {
//             // Initialize tracing subscriber for logging
//             tracing_subscriber::fmt()
//                 .with_max_level(Level::INFO)
//                 .init();

//             // Build the application with the custom middleware layer
//             let app = Router::new()
//                 .route("/", get(hello_world))
//                 // Apply the middleware as a layer
//                 .layer(middleware::from_fn(logging_middleware));

//             // Run the server
//             let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
//             info!("listening on {}", addr);
//             axum::Server::bind(&addr)
//                 .serve(app.into_make_service())
//                 .await
//                 .unwrap();
//         }
//     }
//     mod auth {
//         use axum::{
//             extract::{Extension, State},
//             http::{HeaderMap, StatusCode},
//             middleware::{self, Next},
//             response::{IntoResponse, Json},
//             routing::get,
//             Router,
//         };
//         use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
//         use once_cell::sync::Lazy;
//         use serde::{Deserialize, Serialize};
//         use std::{collections::HashMap, sync::Arc};

//         // --- Configuration and State ---

//         // Secret key for JWT signing/verification. In a real app, load this securely.
//         static KEYS: Lazy<Keys> = Lazy::new(|| {
//             let secret = "your-secret-key"; // Use a strong, persistent key in production
//             Keys::new(secret.as_bytes())
//         });

//         struct Keys {
//             encoding: EncodingKey,
//             decoding: DecodingKey,
//         }

//         impl Keys {
//             fn new(secret: &[u8]) -> Self {
//                 Self {
//                     encoding: EncodingKey::from_secret(secret),
//                     decoding: DecodingKey::from_secret(secret),
//                 }
//             }
//         }

//         // User role definition
//         #[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Hash)]
//         enum Role {
//             User,
//             Admin,
//         }

//         // Claims in the JWT
//         #[derive(Debug, Deserialize, Serialize)]
//         struct Claims {
//             sub: String, // User ID (subject)
//             role: Role,
//             exp: usize, // Expiration time
//         }

//         // In-memory user store for RBAC (mapping user ID to Role)
//         // In a real application, this would likely be a database lookup
//         type RbacStore = Arc<HashMap<String, Role>>;

//         // Application state to hold the RBAC store
//         #[derive(Clone)]
//         struct AppState {
//             rbac_store: RbacStore,
//         }

//         // --- Authentication and Authorization Logic (Middleware) ---

//         async fn auth_middleware(
//             State(state): State<AppState>,
//             headers: HeaderMap,
//             mut req: Request,
//             next: Next,
//         ) -> Result<Response, StatusCode> {
//             let auth_header = headers
//                 .get(http::header::AUTHORIZATION)
//                 .and_then(|header| header.to_str().ok())
//                 .ok_or(StatusCode::UNAUTHORIZED)?;

//             if !auth_header.starts_with("Bearer ") {
//                 return Err(StatusCode::UNAUTHORIZED);
//             }

//             let token = &auth_header[7..];

//             // Decode the token
//             let claims = decode::<Claims>(
//                 token,
//                 &KEYS.decoding,
//                 &Validation::default(),
//             )
//             .map_err(|_| StatusCode::UNAUTHORIZED)?
//             .claims;

//             // Verify user role in the in-memory store
//             let user_role = state.rbac_store.get(&claims.sub);
//             if user_role.is_none() || user_role.unwrap() != &claims.role {
//                 return Err(StatusCode::FORBIDDEN); // Token is valid but role doesn't match store
//             }

//             // Insert the claims into request extensions for handler access
//             req.extensions_mut().insert(claims);

//             Ok(next.run(req).await)
//         }

//         // Handler extractor for protected routes
//         #[derive(Debug, Clone, Deserialize, Serialize)]
//         struct CurrentUser(Claims);

//         #[axum::async_trait]
//         impl<S> FromRequestParts<S> for CurrentUser
//         where
//             S: Send + Sync,
//         {
//             type Rejection = StatusCode;

//             async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
//                 // Extract the `CurrentUser` from the request extensions
//                 parts
//                     .extensions
//                     .get::<Claims>()
//                     .cloned()
//                     .map(CurrentUser)
//                     .ok_or(StatusCode::INTERNAL_SERVER_ERROR) // Should be set by middleware
//             }
//         }

//         // --- Route Handlers ---

//         // Public handler
//         async fn public_handler() -> &'static str {
//             "Hello, public user!"
//         }

//         // Login handler (generates a JWT)
//         async fn login_handler() -> Json<String> {
//             let user_id = "test-user-id-123".to_string(); // In a real app, validate credentials first
//             let user_role = Role::User;

//             let expiration = chrono::Utc::now()
//                 .checked_add_days(chrono::Days::new(1))
//                 .expect("valid timestamp")
//                 .timestamp();

//             let claims = Claims {
//                 sub: user_id.clone(),
//                 role: user_role,
//                 exp: expiration as usize,
//             };

//             let token = encode(&Header::default(), &claims, &KEYS.encoding)
//                 .expect("Failed to encode JWT");

//             // Add the user to the in-memory store upon successful "login"
//             // (This is a simplistic in-memory store simulation)
//             // For this example, we populate the store in `main` for simplicity of demonstration
//             // state.rbac_store.lock().unwrap().insert(user_id, user_role);

//             Json(token)
//         }

//         // Protected handler, requires valid JWT and role
//         async fn protected_handler(CurrentUser(user): CurrentUser) -> String {
//             format!("Hello, protected user: {} with role {:?}", user.sub, user.role)
//         }

//         // Admin-only handler, requires admin role (not fully implemented in the generic middleware above,
//         // but the role is available in `CurrentUser` for a specific handler check or a more granular middleware)
//         async fn admin_handler(CurrentUser(user): CurrentUser) -> Result<String, StatusCode> {
//             if user.role == Role::Admin {
//                 Ok(format!("Welcome admin: {}", user.sub))
//             } else {
//                 Err(StatusCode::FORBIDDEN)
//             }
//         }

//         // --- Main Application Setup ---

//         use axum::extract::FromRequestParts;
//         use axum::http::request::Parts;
//         use axum::response::Response;
//         use axum::Request;

//         #[tokio::main]
//         async fn main() {
//             // Setup in-memory RBAC store with some initial users
//             let mut rbac_map = HashMap::new();
//             rbac_map.insert("test-user-id-123".to_string(), Role::User);
//             rbac_map.insert("admin-user-id-456".to_string(), Role::Admin);
//             let rbac_store = Arc::new(rbac_map);

//             let app_state = AppState { rbac_store };

//             // Build the application routes
//             let app = Router::new()
//                 .route("/public", get(public_handler))
//                 .route("/login", get(login_handler)) // Using GET for simplicity, should be POST in production
//                 // Apply the auth middleware to protected routes
//                 .route_layer(middleware::from_fn_with_state(app_state.clone(), auth_middleware))
//                 .route("/protected", get(protected_handler))
//                 .route("/admin", get(admin_handler))
//                 .with_state(app_state); // Share state with all handlers

//             // Run the server
//             let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//             println!("Server running on http://0.0.0.0:3000");
//             axum::serve(listener, app).await.unwrap();
//         }

//         // Add the necessary imports:
//         use std::sync::Mutex;
//         // ... other imports from the previous example

//         // --- Updated Claims and State ---

//         #[derive(Debug, Deserialize, Serialize, Clone)]
//         struct Claims {
//             sub: String, // User ID (subject)
//             role: Role,
//             exp: usize, // Expiration time
//             jti: String, // JWT ID for token pair tracking
//         }

//         // In-memory store for active refresh tokens.
//         // Stores jti (JWT ID) of the refresh token to allow validation and invalidation.
//         type RefreshTokenStore = Arc<Mutex<HashMap<String, String>>>;

//         #[derive(Clone)]
//         struct AppState {
//             rbac_store: RbacStore,
//             refresh_tokens: RefreshTokenStore, // Add refresh token store
//         }

//         // --- Helper Functions ---

//         // Function to generate a new token
//         fn generate_token(user_id: &str, role: Role, expiration_days: u64, jti: String) -> String {
//             let expiration = chrono::Utc::now()
//                 .checked_add_days(chrono::Days::new(expiration_days))
//                 .expect("valid timestamp")
//                 .timestamp();

//             let claims = Claims {
//                 sub: user_id.to_string(),
//                 role,
//                 exp: expiration as usize,
//                 jti,
//             };

//             encode(&Header::default(), &claims, &KEYS.encoding)
//                 .expect("Failed to encode JWT")
//         }

//         // --- Handlers ---

//         // Updated Login handler (generates both access and refresh tokens)
//         #[derive(Serialize)]
//         struct AuthTokens {
//             access_token: String,
//             refresh_token: String,
//         }

//         async fn login_handler(State(state): State<AppState>) -> Json<AuthTokens> {
//             let user_id = "admin-user-id-456".to_string(); // Example admin user
//             let user_role = Role::Admin;

//             // Generate a unique ID for this login session token pair
//             let session_id = uuid::Uuid::new_v4().to_string();

//             // Access token (short lived, e.g., 30 minutes)
//             let access_token = generate_token(&user_id, user_role, 0, session_id.clone()); // 0 days, use a few minutes in production

//             // Refresh token (long lived, e.g., 7 days)
//             let refresh_token = generate_token(&user_id, user_role, 7, session_id.clone());

//             // Store the refresh token JTI in the server-side store
//             state.refresh_tokens.lock().unwrap().insert(session_id, user_id);

//             Json(AuthTokens { access_token, refresh_token })
//         }

//         // New Refresh Token handler
//         async fn refresh_token_handler(
//             State(state): State<AppState>,
//             headers: HeaderMap,
//         ) -> Result<Json<AuthTokens>, StatusCode> {
//             let auth_header = headers
//                 .get(http::header::AUTHORIZATION)
//                 .and_then(|header| header.to_str().ok())
//                 .ok_or(StatusCode::UNAUTHORIZED)?;

//             if !auth_header.starts_with("Bearer ") {
//                 return Err(StatusCode::UNAUTHORIZED);
//             }

//             let token = &auth_header[7..];

//             // Decode the *refresh* token
//             let claims = decode::<Claims>(
//                 token,
//                 &KEYS.decoding,
//                 &Validation::default(),
//             )
//             .map_err(|_| StatusCode::UNAUTHORIZED)?
//             .claims;

//             // Validate the refresh token's JTI against the server-side store
//             let store = state.refresh_tokens.lock().unwrap();
//             if !store.contains_key(&claims.jti) {
//                 return Err(StatusCode::FORBIDDEN); // Token is not recognized or was revoked
//             }

//             // Check if the user ID from the token matches the stored user ID
//             if let Some(user_id) = store.get(&claims.jti) {
//                 if user_id != &claims.sub {
//                      return Err(StatusCode::FORBIDDEN);
//                 }
//             } else {
//                 return Err(StatusCode::FORBIDDEN);
//             }

//             // If valid, issue a *new* access token (and optionally a new refresh token with rotation)
//             // For simplicity here, we issue just a new access token
//             let new_access_token = generate_token(&claims.sub, claims.role, 0, claims.jti.clone());

//             Ok(Json(AuthTokens {
//                 access_token: new_access_token,
//                 refresh_token: token.to_string() // Return same refresh token if not doing token rotation
//             }))
//         }

//         // --- Main Application Setup ---

//         #[tokio::main]
//         async fn main() {
//             // ... (RbacStore setup as before) ...
//             let rbac_store = Arc::new(HashMap::new()); // simplified for this snippet

//             // Setup refresh token store
//             let refresh_tokens = Arc::new(Mutex::new(HashMap::new()));

//             let app_state = AppState { rbac_store, refresh_tokens };

//             let app = Router::new()
//                 // ... (Public routes) ...
//                 .route("/login", get(login_handler))
//                 .route("/refresh", post(refresh_token_handler)) // Add the refresh route
//                 // ... (Protected routes with middleware as before) ...
//                 .with_state(app_state);

//             // ... (Server run logic) ...
//         }
//     }
//     mod cache {
//         use axum::{
//             Router,
//             extract::Path,
//             routing::get,
//         };
//         use axum_response_cache::CacheLayer;
//         use std::time::Duration;
//         use cached::TimedSizedCache;

//         #[tokio::main]
//         async fn main() {
//             // 1. Initialize the cache: a timed, sized cache with a capacity of 100 items.
//             let cache: TimedSizedCache<String, axum::response::Response> =
//                 TimedSizedCache::with_size_and_lifespan(100, 60);

//             // 2. Create the CacheLayer with a default duration for routes where the header is not set.
//             let cache_layer = CacheLayer::new(cache)
//                 .with_cache_duration(Duration::from_secs(60)); // Responses are cached for 60 seconds by default.

//             // 3. Define the application routes.
//             let app = Router::new()
//                 // This route uses the CacheLayer for caching responses based on the unique {name} path parameter.
//                 .route(
//                     "/hello/:name",
//                     get(|Path(name): Path<String>| async move {
//                         // In a real application, this function would perform expensive operations
//                         // (e.g., database query, API call) that you want to cache.
//                         format!("Hello, {name}! This response is cached.")
//                     })
//                 )
//                 // Apply the caching middleware to the specific route(s).
//                 .layer(cache_layer);

//             // 4. Run the server.
//             let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
//                 .await
//                 .unwrap();

//             println!("Listening on http://127.0.0.1:3000");
//             axum::serve(listener, app).await.unwrap();
//         }
//     }
//     mod cors {
//         use axum::{
//             http::{header, Method, StatusCode},
//             routing::get,
//             Router,
//         };
//         use tower_http::cors::{AllowOrigin, CorsLayer};
//         use std::time::Duration;

//         async fn handler() -> StatusCode {
//             StatusCode::OK
//         }

//         #[tokio::main]
//         async fn main() {
//             // Define the specific origin you want to allow.
//             // This effectively prevents cross-origin requests from any other domain.
//             const ALLOWED_ORIGIN: &'static str = "http://localhost:3000";

//             let cors_layer = CorsLayer::new()
//                 // Allow only the specified origin
//                 .allow_origin(AllowOrigin::list([
//                     ALLOWED_ORIGIN.parse().expect("Invalid origin URL"),
//                 ]))
//                 // Allow the methods needed by your application, e.g., GET and POST
//                 .allow_methods([Method::GET, Method::POST])
//                 // Allow specific headers
//                 .allow_headers([header::CONTENT_TYPE])
//                 // Max age for preflight requests, prevents repeated OPTIONS calls
//                 .max_age(Duration::from_secs(60) * 10);

//             let app = Router::new()
//                 .route("/", get(handler).post(handler))
//                 // Apply the restrictive CORS layer globally to the router
//                 .layer(cors_layer);

//             // Run the application
//             let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
//                 .await
//                 .unwrap();
//             println!("Listening on http://localhost:3000");
//             axum::serve(listener, app).await.unwrap();
//         }
//     }
//     mod csrf {
//         use askama::Template;
//         use axum::{
//             Form,
//             response::IntoResponse,
//             routing::{get, post},
//             Router,
//         };
//         use axum_csrf::{CsrfConfig, CsrfLayer, CsrfToken};
//         use serde::{Deserialize, Serialize};
//         use std::net::SocketAddr;

//         // A simple template for demonstration (requires 'template.html' file in a 'templates' directory)
//         #[derive(Template, Deserialize, Serialize)]
//         #[template(path = "template.html")]
//         struct Keys {
//             authenticity_token: String,
//         }

//         #[tokio::main]
//         async fn main() {
//             // Basic setup...

//             let config = CsrfConfig::default();

//             let app = Router::new()
//                 .route("/", get(root).post(check_key))
//                 .layer(CsrfLayer::new(config)); // Apply the CSRF layer

//             // Run server...
//         }

//         // Handler to generate and include the CSRF token
//         async fn root(token: CsrfToken) -> impl IntoResponse {
//             let keys = Keys {
//                 authenticity_token: token.authenticity_token().unwrap(),
//             };
//             (token, keys).into_response()
//         }

//         // Handler to validate the submitted token
//         async fn check_key(token: CsrfToken, Form(payload): Form<Keys>) -> &'static str {
//             if token.verify(&payload.authenticity_token).is_err() {
//                 "Token is invalid"
//             } else {
//                 "Token is Valid lets do stuff!"
//             }
//         }
//     }
//     mod xss {
//         use axum::{
//             extract::Form,
//             response::Html,
//             routing::{get, post},
//             Router,
//         };
//         use serde::Deserialize;
//         use ammonia::clean; // Import the clean function

//         // A struct to model the input data from the HTML form
//         #[derive(Debug, Deserialize)]
//         struct UserComment {
//             username: String,
//             comment: String,
//         }

//         #[tokio::main]
//         async fn main() {
//             // build our application with a route
//             let app = Router::new()
//                 .route("/", get(show_form))
//                 .route("/submit_comment", post(handle_submit));

//             // run our app with hyper
//             let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//             println!("Server listening on http://0.0.0.0:3000");
//             axum::serve(listener, app).await.unwrap();
//         }

//         // Handler to display the input form
//         async fn show_form() -> Html<String> {
//             Html(r#"
//             <!DOCTYPE html>
//             <html>
//             <body>
//                 <h2>Submit a Comment</h2>
//                 <form action="/submit_comment" method="post">
//                     <label for="username">Username:</label><br>
//                     <input type="text" id="username" name="username" value="Anonymous"><br>
//                     <label for="comment">Comment (some HTML allowed):</label><br>
//                     <textarea id="comment" name="comment" rows="4" cols="50"></textarea><br><br>
//                     <input type="submit" value="Submit">
//                 </form>
//             </body>
//             </html>
//             "#.to_string())
//         }

//         // Handler to process the form submission
//         async fn handle_submit(Form(user_comment): Form<UserComment>) -> Html<String> {
//             // Sanitize the comment using ammonia::clean()
//             // This removes dangerous tags/attributes like <script> or onerror
//             let sanitized_comment = clean(&user_comment.comment);

//             // Use the username and sanitized comment in the response
//             let response_html = format!(
//                 "<h3>Comment Received</h3>
//                 <p><strong>Username:</strong> {}</p>
//                 <p><strong>Comment:</strong> {}</p>
//                 <a href='/'>Go back</a>",
//                 // The username should be HTML-encoded if it can contain HTML
//                 // If it's expected to be just text, displaying it directly is fine
//                 // but for full safety, use a proper templating engine that auto-escapes.
//                 html_escape::encode_safe(&user_comment.username),
//                 sanitized_comment
//             );

//             Html(response_html)
//         }
//     }
//     mod validate {
//         use axum::{routing::post, Router};
//         use axum_valid::Valid;
//         use serde::Deserialize;
//         use validator::Validate;

//         // 1. Define the data structure with validation rules.
//         #[derive(Debug, Deserialize, Validate)]
//         pub struct CreateUser {
//             // Validate that the username has a minimum length of 3.
//             #[validate(length(min = 3))]
//             pub username: String,
//             // Validate that the email is a valid email format.
//             #[validate(email)]
//             pub email: String,
//             // Validate the URL starts with a safe protocol (http/https)
//             #[validate(url(protocols = &["http", "https"]))]
//             pub website: String,
//         }

//         // 2. Use the `Valid` extractor in your handler.
//         // Axum will automatically return a 400 Bad Request if validation fails.
//         async fn create_user(Valid(user): Valid<CreateUser>) -> String {
//             // The 'user' is guaranteed to be valid here.
//             format!("User created with valid username: {}", user.username)
//         }

//         // 3. Set up the router.
//         fn app_router() -> Router {
//             Router::new().route("/users", post(create_user))
//         }
//     }
//     mod rate-limit {
//         use axum::{
//             error_handling::HandleErrorLayer,
//             routing::get,
//             BoxError,
//             Router,
//         };
//         use http::StatusCode;
//         use std::{net::SocketAddr, sync::Arc, time::Duration};
//         use tower::ServiceBuilder;
//         use tower_governor::{
//             governor::{GovernorConfigBuilder, GovernorConfig},
//             GovernorLayer,
//             // Use the SmartIpKeyExtractor to handle cases where your app is behind a reverse proxy
//             // it falls back to the peer IP if no headers are present
//             key_extractor::SmartIpKeyExtractor,
//         };
//         use tracing_subscriber::{fmt, prelude::*, EnvFilter};

//         async fn handler() -> &'static str {
//             "Hello, limited world!"
//         }

//         #[tokio::main]
//         async fn main() {
//             // Initialize tracing for better logging and visibility
//             tracing_subscriber::registry()
//                 .with(fmt::layer())
//                 .with(EnvFilter::from_default_env())
//                 .init();

//             // 1. Configure the rate limiter
//             // Allow bursts with up to 5 requests per IP address and replenishes 1 element every 1 second (5 per minute)
//             let governor_conf = Box::new(
//                 GovernorConfigBuilder::default()
//                     .per_second(1) // replenished every 1 second
//                     .burst_size(5) // max burst size of 5 requests
//                     .finish()
//                     .unwrap(),
//             );

//             // The configuration needs a static lifetime to be used with the layer.
//             // Box::leak is a way to achieve this for demonstration purposes. In a real app, manage this carefully.
//             let governor_conf: &'static GovernorConfig = Box::leak(governor_conf);

//             // 2. Create the Axum router
//             let app = Router::new()
//                 .route("/", get(handler))
//                 .route("/unlimited", get(handler)) // This route will be rate-limited too, because the layer is applied globally
//                 .layer(
//                     ServiceBuilder::new()
//                         // Handle errors from the rate limiter layer
//                         .layer(HandleErrorLayer::new(|e: BoxError| async move {
//                             StatusCode::TOO_MANY_REQUESTS
//                         }))
//                         // Apply the rate limiting layer using SmartIpKeyExtractor for IP detection
//                         .layer(GovernorLayer::new(governor_conf, SmartIpKeyExtractor)),
//                 );

//             // 3. Run the application
//             let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
//             tracing::info!("Listening on {}", addr);
//             axum::serve(
//                 tokio::net::TcpListener::bind(addr).await.unwrap(),
//                 app.into_make_service_with_connect_info::<SocketAddr>(),
//             )
//             .await
//             .unwrap();
//         }
//     }
//     mod size-limit {
//         use axum::{
//             Router,
//             routing::post,
//             extract::DefaultBodyLimit,
//             http::StatusCode,
//             response::IntoResponse,
//         };
//         use std::net::SocketAddr;

//         // A handler that accepts a String body.
//         // If the body exceeds the limit set by the layer, axum will return a 413 Payload Too Large error automatically.
//         async fn handler(body: String) -> impl IntoResponse {
//             format!("Received body with length: {}", body.len())
//         }

//         #[tokio::main]
//         async fn main() {
//             // Set the maximum body size to 1024 bytes (1 KB)
//             let app = Router::new()
//                 .route("/", post(handler))
//                 .layer(DefaultBodyLimit::max(1024)); //

//             // run our app with hyper
//             let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
//             println!("listening on {}", addr);
//             axum::Server::bind(&addr)
//                 .serve(app.into_make_service())
//                 .await
//                 .unwrap();
//         }
//     }
//     mod time-limit {
//         use axum::{
//             routing::get,
//             error_handling::HandleErrorLayer,
//             http::{StatusCode, Request, Method, Uri},
//             BoxError,
//             Router,
//         };
//         use tower::{ServiceBuilder, timeout::TimeoutLayer};
//         use std::time::Duration;
//         use tower_http::trace::TraceLayer;
//         use axum::response::IntoResponse;

//         // The slow handler that will intentionally exceed the timeout
//         async fn slow_handler() -> impl IntoResponse {
//             // Simulate a time-consuming operation
//             tokio::time::sleep(Duration::from_secs(2)).await;
//             "This response might be late!"
//         }

//         // The error handler for the timeout error
//         fn handle_timeout_error(method: Method, uri: Uri, err: BoxError) -> (StatusCode, String) {
//             if err.is::<tower::timeout::error::Elapsed>() {
//                 (
//                     StatusCode::REQUEST_TIMEOUT,
//                     format!("Request to {} {} took too long", method, uri),
//                 )
//             } else {
//                 (
//                     StatusCode::INTERNAL_SERVER_ERROR,
//                     format!("Unhandled internal error: {}", err),
//                 )
//             }
//         }

//         #[tokio::main]
//         async fn main() {
//             // Define the timeout duration
//             const TIMEOUT_DURATION: Duration = Duration::from_secs(1);

//             // Build the middleware stack using ServiceBuilder
//             let middleware_stack = ServiceBuilder::new()
//                 // The HandleErrorLayer must be placed above the TimeoutLayer
//                 // so it can catch the error produced when a timeout occurs
//                 .layer(HandleErrorLayer::new(handle_timeout_error))
//                 // Apply the timeout layer
//                 .layer(TimeoutLayer::new(TIMEOUT_DURATION));

//             // Create the router and apply the middleware
//             let app = Router::new()
//                 .route("/slow", get(slow_handler))
//                 // Apply the middleware to all routes in the application
//                 .layer(middleware_stack);

//             // Run the server
//             let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
//                 .await
//                 .unwrap();
//             println!("Listening on http://127.0.0.1:3000");
//             axum::serve(listener, app)
//                 .await
//                 .unwrap();
//         }
// }
