/*
...existing code...
jsonwebtoken = "9"
axum-extra = { version = "0.9", features = ["typed-header"] }
...existing code...
 */

 /*
 ...existing code...
use axum_extra::headers::{authorization::Bearer, Authorization};
use axum::extract::TypedHeader;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};

const JWT_SECRET: &[u8] = b"your_secret_key_change_me";

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// Handler for /login to issue JWTs
async fn login(Json(payload): Json<HashMap<String, String>>) -> impl IntoResponse {
    let username = payload.get("username").cloned().unwrap_or_default();
    if username.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Missing username"})));
    }
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .unwrap()
        .timestamp() as usize;
    let claims = Claims { sub: username, exp: expiration };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    ).unwrap();
    (StatusCode::OK, Json(json!({ "token": token })))
}

// Auth middleware
async fn auth<B>(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    req: axum::http::Request<B>,
    next: axum::middleware::Next<B>,
) -> impl IntoResponse {
    let token_data = decode::<Claims>(
        auth.token(),
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::new(Algorithm::HS256),
    );
    match token_data {
        Ok(_) => next.run(req).await,
        Err(_) => (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid or expired token"}))).into_response(),
    }
}

#[tokio::main]
async fn main() {
    ...existing code...
    let db = Arc::new(RwLock::new(HashMap::<Uuid, Item>::new()));

    let protected_routes = Router::new()
        .route("/items", get(select_items).post(create_item))
        .route("/items/:id", get(select_item).put(update_item).delete(delete_item))
        .layer(axum::middleware::from_fn(auth))
        .with_state(db.clone());

    let app = Router::new()
        .route("/login", axum::routing::post(login))
        .merge(protected_routes)
        .with_state(db);

    ...existing code...
}
...existing code...
  */
