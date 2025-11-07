/*
dashmap = "5"
*/

/*
use dashmap::DashMap;

// Add this type alias near your Db definition
type Cache = Arc<DashMap<String, serde_json::Value>>;

// In main(), create and share the cache
let cache: Cache = Arc::new(DashMap::new());

let app = Router::new()
    // ...existing routes...
    .with_state(db)
    .layer(axum::extract::Extension(cache.clone())); // Share cache via Extension

// Example: Caching in a handler
#[debug_handler]
async fn select_items(
    State(db): State<Db>,
    Query(params): Query<SelectItems>,
    axum::extract::Extension(cache): axum::extract::Extension<Cache>,
) -> impl IntoResponse {
    let cache_key = format!("{:?}:{:?}", params.name, params.value);
    if let Some(cached) = cache.get(&cache_key) {
        info!("Cache hit for key: {}", cache_key);
        return (StatusCode::OK, Json(cached.value().clone()));
    }
    // ...existing logic to get items...
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
    let items_json = serde_json::to_value(&items).expect("Failed to serialize selected items!");
    cache.insert(cache_key.clone(), items_json.clone());
    info!("Cache miss for key: {}, storing result", cache_key);
    (StatusCode::OK, Json(items_json))
}
*/