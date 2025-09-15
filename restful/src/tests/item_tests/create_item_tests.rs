use super::*;

#[tokio::test]
async fn test_create_item_created() {
    // Create an instance of the app with a shared database
    let app = app_with_db();
    // Create a payload for the create_item request
    let payload = json!({"name" : "create_item", "value" : "created"});
    // Send a POST request to create an item
    let response = app
        .oneshot(
            Request::post("/items")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap())
        .await
        .unwrap();
    // Assert the response status is CREATED (201)
    assert_eq!(response.status(), StatusCode::CREATED);
    // Read the response body and parse it as JSON
    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body)
        .unwrap();
    // Assert the response body contains the requested item
    assert!(body.get("id").is_some());
    assert_eq!(body["name"], payload["name"]);
    assert_eq!(body["value"], payload["value"]);
    // Extract the id from the response body for subsequent tests that depend on the created item
    // let id = body["id"].as_str().unwrap();
}

#[tokio::test]
async fn test_create_item_unprocessable_entity() {
    // Create an instance of the app with a shared database
    let app = app_with_db();
    // Create a payload for the create_item request
    let payload = json!({"name" : "", "value" : ""});
    // Send a POST request to create an item
    let response = app
        .oneshot(
            Request::post("/items")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap())
        .await
        .unwrap();
    // Assert the response status is UNPROCESSABLE_ENTITY (422)
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // Read the response body and parse it as JSON
    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body)
        .unwrap();
    // Assert the response body contains validation errors
    assert!(body.get("errors").is_some());
}
