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

// Add the necessary imports:
use std::sync::Mutex;
// ... other imports from the previous example

// --- Updated Claims and State ---

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Claims {
    sub: String, // User ID (subject)
    role: Role,
    exp: usize, // Expiration time
    jti: String, // JWT ID for token pair tracking
}

// In-memory store for active refresh tokens.
// Stores jti (JWT ID) of the refresh token to allow validation and invalidation.
type RefreshTokenStore = Arc<Mutex<HashMap<String, String>>>; 

#[derive(Clone)]
struct AppState {
    rbac_store: RbacStore,
    refresh_tokens: RefreshTokenStore, // Add refresh token store
}

// --- Helper Functions ---

// Function to generate a new token
fn generate_token(user_id: &str, role: Role, expiration_days: u64, jti: String) -> String {
    let expiration = chrono::Utc::now()
        .checked_add_days(chrono::Days::new(expiration_days))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id.to_string(),
        role,
        exp: expiration as usize,
        jti,
    };

    encode(&Header::default(), &claims, &KEYS.encoding)
        .expect("Failed to encode JWT")
}

// --- Handlers ---

// Updated Login handler (generates both access and refresh tokens)
#[derive(Serialize)]
struct AuthTokens {
    access_token: String,
    refresh_token: String,
}

async fn login_handler(State(state): State<AppState>) -> Json<AuthTokens> {
    let user_id = "admin-user-id-456".to_string(); // Example admin user
    let user_role = Role::Admin;

    // Generate a unique ID for this login session token pair
    let session_id = uuid::Uuid::new_v4().to_string(); 

    // Access token (short lived, e.g., 30 minutes)
    let access_token = generate_token(&user_id, user_role, 0, session_id.clone()); // 0 days, use a few minutes in production

    // Refresh token (long lived, e.g., 7 days)
    let refresh_token = generate_token(&user_id, user_role, 7, session_id.clone());

    // Store the refresh token JTI in the server-side store
    state.refresh_tokens.lock().unwrap().insert(session_id, user_id);

    Json(AuthTokens { access_token, refresh_token })
}

// New Refresh Token handler
async fn refresh_token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AuthTokens>, StatusCode> {
    let auth_header = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    let token = &auth_header[7..];

    // Decode the *refresh* token
    let claims = decode::<Claims>(
        token,
        &KEYS.decoding,
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;

    // Validate the refresh token's JTI against the server-side store
    let store = state.refresh_tokens.lock().unwrap();
    if !store.contains_key(&claims.jti) {
        return Err(StatusCode::FORBIDDEN); // Token is not recognized or was revoked
    }
    
    // Check if the user ID from the token matches the stored user ID
    if let Some(user_id) = store.get(&claims.jti) {
        if user_id != &claims.sub {
             return Err(StatusCode::FORBIDDEN);
        }
    } else {
        return Err(StatusCode::FORBIDDEN);
    }

    // If valid, issue a *new* access token (and optionally a new refresh token with rotation)
    // For simplicity here, we issue just a new access token
    let new_access_token = generate_token(&claims.sub, claims.role, 0, claims.jti.clone());
    
    Ok(Json(AuthTokens { 
        access_token: new_access_token, 
        refresh_token: token.to_string() // Return same refresh token if not doing token rotation
    }))
}


// --- Main Application Setup ---

#[tokio::main]
async fn main() {
    // ... (RbacStore setup as before) ...
    let rbac_store = Arc::new(HashMap::new()); // simplified for this snippet
    
    // Setup refresh token store
    let refresh_tokens = Arc::new(Mutex::new(HashMap::new()));
    
    let app_state = AppState { rbac_store, refresh_tokens };

    let app = Router::new()
        // ... (Public routes) ...
        .route("/login", get(login_handler))
        .route("/refresh", post(refresh_token_handler)) // Add the refresh route
        // ... (Protected routes with middleware as before) ...
        .with_state(app_state);

    // ... (Server run logic) ...
}
 */