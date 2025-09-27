use axum::{body::Body, debug_handler, extract::{Path, Query, State,}, http::StatusCode, Json, middleware, response::IntoResponse, Router, routing::{get, post,}, serve,};
use axum_extra::{headers::{Authorization, authorization::Bearer,}, TypedHeader,};
use chrono::{Duration, Utc,};
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Header, Validation,};
use serde::{Deserialize, Serialize,};
use serde_json::json;
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc,};
use tokio::{net::TcpListener, sync::RwLock,};
use uuid::Uuid;
use validator::{Validate, ValidationErrors,};
use tracing::{error, info, warn,};
use tracing_subscriber;

#[derive(Clone, Deserialize, Serialize)]
struct Item {
    id: Uuid,
    name: String,
    value: String,
}

#[derive(Deserialize, Validate)]
struct CreateItem {
    #[validate(length(min = 1, message = "name field in create_item request is empty"))]
    name: String,
    #[validate(length(min = 1, message = "value field in create_item request is empty"))]
    value: String,
}

#[derive(Deserialize, Validate)]
struct SelectItems {
    #[validate(length(min = 1, message = "name query parameter in select_items request is empty"))]
    name: Option<String>,
    #[validate(length(min = 1, message = "value query parameter in select_items request is empty"))]
    value: Option<String>,
}

#[derive(Deserialize, Validate)]
struct UpdateItem {
    #[validate(length(min = 1, message = "name field in update_item request is empty"))]
    name: Option<String>,
    #[validate(length(min = 1, message = "value field in update_item request is empty"))]
    value: Option<String>,
}

#[derive(Deserialize, Validate)]
struct Signin {
    #[validate(length(min = 1, message = "username field in signin request is empty"))]
    username: String,
    #[validate(length(min = 1, message = "password field in signin request is empty"))]
    password: String,
}

#[derive(Deserialize, Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

type Db = Arc<RwLock<HashMap<Uuid, Item>>>;

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber for logging with debug level
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    // Create a shared database using Arc, RwLock and an empty HashMap
    let db = Arc::new(RwLock::new(HashMap::<Uuid, Item>::new()));
    // Create the protected, CRUD routes for Items with Middleware to check for valid JWT    
    let item_routes = Router::new()
        .route("/items", get(select_items).post(create_item))
        .route("/items/{id}", get(select_item).put(update_item).delete(delete_item))
        .layer(middleware::from_fn(authrz))
        .with_state(db.clone());
    // Create the Axum application with routes and shared database
    let app = Router::new()
        .route("/login", post(signin))
        .merge(item_routes)
        .with_state(db);
    // Define the address for the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    // Bind the TCP listener to the specified address
    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind address!");
    // Log the address where the server is listening
    info!("Listening on http://{}", addr);
    // Start the Axum server with the listener and application
    serve(listener, app)
        .await
        .expect("Failed to start service!");
}

// handler function for POST /items
#[debug_handler]
async fn create_item(
    State(db): State<Db>,
    Json(payload): Json<CreateItem>,
) -> impl IntoResponse {
    // Log create_item request recieved
    info!("Recieved create_item request: name={:?} value={:?}", payload.name, payload. value);
    // Validate the request
    if let Err(errors) = payload.validate() {
    // Log validation failed
    error!("Failed create_item validation: {:?}", errors);
    // Respond with 422 status and errors in JSON format
        return 
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"errors": validation_errors_to_map(errors)})),
        );
    }
    // Lock the database for write
    let mut db = db.write().await;
    // Create new item
    let item = Item {
        id: Uuid::new_v4(),
        name: payload.name,
        value: payload.value,
    };
    // Insert the item into the database
    db.insert(item.id, item.clone());
    // Log item inserted
    info!("Inserted item into database: id={}", item.id);
    // Respond with 201 status and item in JSON format
    (
        StatusCode::CREATED, 
        Json(serde_json::to_value(item).expect("Failed to serialize created item!"))
    )
}

// handler function for GET /items
#[debug_handler]
async fn select_items(
    State(db): State<Db>,
    Query(params): Query<SelectItems>, 
) -> impl IntoResponse {
    // Log select_items request recieved
    info!("Recieved select_items request: name={:?} value={:?}", params.name, params.value);
    // Validate the request
    if let Err(errors) = params.validate() {
    // Log validation failed
    error!("Failed select_items validation: {:?}", errors);
    // Respond with 422 status and errors in JSON format
        return 
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"errors": validation_errors_to_map(errors)})),
        );
    }
    // Get existing items and filter on query parameters
    let items: Vec<Item> = db
        .read()
        .await
        .values()
        .cloned()
        .filter(|item| {
            let name_matched = params.name.as_ref().map_or(true, |params_name| item.name == *params_name);
            let value_matched = params.value.as_ref().map_or(true, |params_value| item.value == *params_value);
            name_matched && value_matched
        })
        .collect();
    // Log items found
    info!("Found {} items in database", items.len());
    // Respond with 200 status and items in JSON format
    (
        StatusCode::OK,
        Json(serde_json::to_value(items).expect("Failed to serialize selected items!"))
    )
}

//handler function for PUT /items/{id}
#[debug_handler]
async fn update_item(
    State(db): State<Db>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateItem>,    
) -> impl IntoResponse {
    // Log update_item request recieved
    info!("Recieved update_item request: id={}", id);
    // Validate the request
    if let Err(errors) = payload.validate() {
        // Log validation failed
        error!("Failed update_item validation: {:?}", errors);
        // Respond with 422 status and errors in JSON format
        return 
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"errors": validation_errors_to_map(errors)})),
        );
    }
    // Lock the database for write
    let mut db = db.write().await;
    // Get existing item
    if let Some(item) = db.get_mut(&id) {
        // Update found item in database with just fields provided
        if let Some(name) = &payload.name {
            item.name = name.clone();
        }
        if let Some(value) = &payload.value {
            item.value = value.clone();
        }
        // Log item updated
        info!("Updated item in database: id={}", id);
        // Respond with 200 status and item in JSON format
        (
            StatusCode::OK, 
            Json(serde_json::to_value(item.clone()).expect("Failed to serialize updated item!"))
        )
    } else {
        // Log item not found
        warn!("Failed to find item: id={}", id);
        // Respond with 204 status and empty body
        (
            StatusCode::NO_CONTENT, 
            Json(serde_json::to_value(Item {
                id,
                name: "".to_string(),
                value: "".to_string(),
            }).expect("Failed to serialize empty item!"))
        )
    }
}

//handler function for GET /items/{id}
#[debug_handler]
async fn select_item(
    State(db): State<Db>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Log select_item request recieved
    info!("Recieved select_item request: id={}", id);
    let db = db.read().await;
    // Get existing item
    if let Some(item) = db.get(&id) {
        // Log item found
        info!("Found item in database: id={}", id);
        // Respond with 200 status and item in JSON format
        (
            StatusCode::OK, 
            Json(item.clone())
        )
    } else {
        // Log item not found
        warn!("Failed to find item: id={}", id);
        // Respond with 204 status and empty body
        (
            StatusCode::NO_CONTENT, 
            Json(Item {
                id,
                name: "".to_string(),
                value: "".to_string(),
            })
        )
    }
}

//handler function for DELETE /items/{id}
#[debug_handler]
async fn delete_item(
    State(db): State<Db>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Log delete_item request recieved
    info!("Recieved delete_item request: id={}", id);
    // Lock the database for write
    let mut db = db.write().await;
    // Remove item from database
    if db.remove(&id).is_some() {
        // Log item removed
        info!("Removed item in database: id={}", id);
        // Respond with 200 status and empty object in JSON format
        StatusCode::OK.into_response()
    } else {
        // Log item not found
        warn!("Failed to find item: id={}", id);
        // Respond with 204 status and empty object in JSON format
        StatusCode::NO_CONTENT.into_response()
    }
}

// Helper function to convert ValidationErrors to a map for JSON response
fn validation_errors_to_map(errors: ValidationErrors) -> serde_json::Value {
    // Create a map to hold field errors
    let mut map = serde_json::Map::new();
    // Iterate over field errors and collect messages
    for (field, errs) in errors.field_errors().iter() {
        // Collect messages for each field error
        let messages: Vec<String> = errs.iter().filter_map(|err| err.message.as_ref().map(|message| message.to_string())).collect();
        // Insert the field and its messages into the map
        map.insert(field.to_string(), json!(messages));
    }
    json!(map)
}

// Helper function to get the JWT secret at runtime
fn jwt_secret() -> Vec<u8> {
    env::var("JWT_SECRET")
    .expect("JWT_SECRET environment variable is empty!")
    .as_bytes()
    .to_vec()
} // Use &jwt_secret() in encode and decode functions

// Handler function for POST /login
async fn signin(
    Json(payload): Json<Signin>
) -> impl IntoResponse {
    // Log signin request recieved
    info!("Recieved signin request");
    // Validate the request
    if let Err(errors) = payload.validate() {
    // Log validation failed
    error!("Failed signin validation: {:?}", errors);
    // Respond with 422 status and errors in JSON format
        return 
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"errors": validation_errors_to_map(errors)})),
        );
    }
    // Create JWT token with username and expiration claims
    let username = payload.username;
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("Failed to set expiration time!")
        .timestamp() as usize;
    let claims = Claims {
        sub: username,
        exp: expiration,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&jwt_secret()),)
        .expect("Failed to encode token!");
    // Respond with 200 status and token in JSON format
    (
        StatusCode::OK, 
        Json(json!({"token": token}))
    )
}

// Helper function for  middleware
async fn authrz(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    req: axum::http::Request<Body>,
    next: middleware::Next,
) -> impl IntoResponse {
    let token_data = decode::<Claims>(
        auth.token(),
        &DecodingKey::from_secret(&jwt_secret()),
        &Validation::new(Algorithm::HS256),
    );
    match token_data {
        Ok(_) => next.run(req).await,
        Err(_) => (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid or expired token"}))).into_response(),
    }
}

#[cfg(test)]
mod tests;
