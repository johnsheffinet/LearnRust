use super::*;

#[tokio::test]
async fn test_update_item_ok() {
    // Create an instance of the app with a shared database
    let app = app_with_db();
    // Create a payload for the create_item request
    let create_payload = json!({"name" : "update_item", "value" : "created"});
    // Send a POST request to create an item
    let response = app
        .clone()
        .oneshot(
            Request::post("/items")
                .header("content-type", "application/json")
                .body(Body::from(create_payload.to_string()))
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
    assert_eq!(body["name"], create_payload["name"]);
    assert_eq!(body["value"], create_payload["value"]);
    // Extract the id from the response body for subsequent tests that depend on the created item
    let id = body["id"].as_str().unwrap();
    // Create a payload for the update_item request
    let update_payload = json!({/*"name" : "update_item",*/ "value" : "ok"});
    // Send a PUT request to update an item
    let response = app
        .oneshot(
            Request::put(format!("/items/{}", id))
                .header("content-type", "application/json")
                .body(Body::from(update_payload.to_string()))
                .unwrap())
        .await
        .unwrap();
    // Assert the response status is OK (200)
    assert_eq!(response.status(), StatusCode::OK);
    // Read the response body and parse it as JSON
    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body)
        .unwrap();
    // Assert the response body contains the requested item
    assert_eq!(body["id"].as_str().unwrap(), id);
    assert_eq!(body["name"], create_payload["name"]);
    assert_eq!(body["value"], update_payload["value"]);
}

#[tokio::test]
async fn test_update_item_unprocessable_entity() {
    // Create an instance of the app with a shared database
    let app = app_with_db();
    // Create a payload for the create_item request
    let create_payload = json!({"name" : "update_item", "value" : "created"});
    // Send a POST request to create an item
    let response = app
        .clone()
        .oneshot(
            Request::post("/items")
                .header("content-type", "application/json")
                .body(Body::from(create_payload.to_string()))
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
    assert_eq!(body["name"], create_payload["name"]);
    assert_eq!(body["value"], create_payload["value"]);
    // Extract the id from the response body for subsequent tests that depend on the created item
    let id = body["id"].as_str().unwrap();
    // Create a payload for the update_item request
    let update_payload = json!({"name" : "", "value" : ""});
    // Send a PUT request to update an item
    let response = app
        .oneshot(
            Request::put(format!("/items/{}", id))
                .header("content-type", "application/json")
                .body(Body::from(update_payload.to_string()))
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

#[tokio::test]
async fn test_update_item_no_content() {
    // Create an instance of the app with a shared database
    let app = app_with_db();
    // Assign an id that doesn't exist in the database
    let id = String::from("00000000-0000-0000-0000-000000000000");
    // Create a payload for the update_item request
    let payload = json!({"name" : "update_item", "value" : "no%20content"});
    // Send a PUT request to update an item
    let response = app
        .oneshot(
            Request::put(format!("/items/{}", id))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap())
        .await
        .unwrap();
    // Assert the response status is NO_CONTENT (204)
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
