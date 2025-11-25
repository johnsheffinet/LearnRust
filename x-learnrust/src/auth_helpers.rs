/*
use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

// --- Configuration and State ---

// Secret key for JWT signing/verification. In a real app, load this securely.
static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = "your-secret-key"; // Use a strong, persistent key in production
    Keys::new(secret.as_bytes())
});

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

// User role definition
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Hash)]
enum Role {
    User,
    Admin,
}

// Claims in the JWT
#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String, // User ID (subject)
    role: Role,
    exp: usize, // Expiration time
}

// In-memory user store for RBAC (mapping user ID to Role)
// In a real application, this would likely be a database lookup
type RbacStore = Arc<HashMap<String, Role>>;

// Application state to hold the RBAC store
#[derive(Clone)]
struct AppState {
    rbac_store: RbacStore,
}

// --- Authentication and Authorization Logic (Middleware) ---

async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header[7..];

    // Decode the token
    let claims = decode::<Claims>(
        token,
        &KEYS.decoding,
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;

    // Verify user role in the in-memory store
    let user_role = state.rbac_store.get(&claims.sub);
    if user_role.is_none() || user_role.unwrap() != &claims.role {
        return Err(StatusCode::FORBIDDEN); // Token is valid but role doesn't match store
    }
    
    // Insert the claims into request extensions for handler access
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

// Handler extractor for protected routes
#[derive(Debug, Clone, Deserialize, Serialize)]
struct CurrentUser(Claims);

#[axum::async_trait]
impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the `CurrentUser` from the request extensions
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .map(CurrentUser)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR) // Should be set by middleware
    }
}

// --- Route Handlers ---

// Public handler
async fn public_handler() -> &'static str {
    "Hello, public user!"
}

// Login handler (generates a JWT)
async fn login_handler() -> Json<String> {
    let user_id = "test-user-id-123".to_string(); // In a real app, validate credentials first
    let user_role = Role::User;

    let expiration = chrono::Utc::now()
        .checked_add_days(chrono::Days::new(1))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id.clone(),
        role: user_role,
        exp: expiration as usize,
    };

    let token = encode(&Header::default(), &claims, &KEYS.encoding)
        .expect("Failed to encode JWT");

    // Add the user to the in-memory store upon successful "login"
    // (This is a simplistic in-memory store simulation)
    // For this example, we populate the store in `main` for simplicity of demonstration
    // state.rbac_store.lock().unwrap().insert(user_id, user_role);

    Json(token)
}

// Protected handler, requires valid JWT and role
async fn protected_handler(CurrentUser(user): CurrentUser) -> String {
    format!("Hello, protected user: {} with role {:?}", user.sub, user.role)
}

// Admin-only handler, requires admin role (not fully implemented in the generic middleware above,
// but the role is available in `CurrentUser` for a specific handler check or a more granular middleware)
async fn admin_handler(CurrentUser(user): CurrentUser) -> Result<String, StatusCode> {
    if user.role == Role::Admin {
        Ok(format!("Welcome admin: {}", user.sub))
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

// --- Main Application Setup ---

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::Response;
use axum::Request;

#[tokio::main]
async fn main() {
    // Setup in-memory RBAC store with some initial users
    let mut rbac_map = HashMap::new();
    rbac_map.insert("test-user-id-123".to_string(), Role::User);
    rbac_map.insert("admin-user-id-456".to_string(), Role::Admin);
    let rbac_store = Arc::new(rbac_map);

    let app_state = AppState { rbac_store };

    // Build the application routes
    let app = Router::new()
        .route("/public", get(public_handler))
        .route("/login", get(login_handler)) // Using GET for simplicity, should be POST in production
        // Apply the auth middleware to protected routes
        .route_layer(middleware::from_fn_with_state(app_state.clone(), auth_middleware))
        .route("/protected", get(protected_handler))
        .route("/admin", get(admin_handler))
        .with_state(app_state); // Share state with all handlers

    // Run the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
 */
