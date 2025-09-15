use super::*;

pub use axum::{body::{self, Body}, http::{Request, StatusCode}, routing::get, Router,};
pub use serde_json::json;
pub use tower::ServiceExt;

pub fn app_with_db() -> Router {
    let db = Arc::new(RwLock::new(HashMap::<Uuid, Item>::new()));

    Router::new()
        .route("/items", get(select_items).post(create_item))
        .route("/items/{id}", get(select_item).put(update_item).delete(delete_item))
        .with_state(db)
}

mod create_item_tests;
mod delete_item_tests;
mod select_item_tests;
mod select_items_tests;
mod update_item_tests;