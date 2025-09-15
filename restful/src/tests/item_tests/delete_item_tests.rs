use super::*;

#[tokio::test]
async fn test_delete_item_ok() {
    // Create an instance of the app with a shared database
    let app = app_with_db();
    // Create a payload for the create_item request
    let payload = json!({"name" : "delete_item", "value" : "created"});
    // Send a POST request to create an item
    let response = app
        .clone()
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
    let id = body["id"].as_str().unwrap();
    // Send a DELETE request to delete an item
    let response = app
        .clone()
        .oneshot(
            Request::delete(format!("/items/{}", id))
                .body(Body::empty())
                .unwrap())
        .await
        .unwrap();
    // Assert the response status is OK (200)
    assert_eq!(response.status(), StatusCode::OK);
    // Send a GET request to select an item
    let response = app
        .oneshot(
            Request::get(format!("/items/{}", id))
                .body(Body::empty())
                .unwrap())
        .await
        .unwrap();
    // Assert the response status is NO_CONTENT (204)
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_item_no_content() {
    // Create an instance of the app with a shared database
    let app = app_with_db();
    // Assign an id that doesn't exist in the database
    let id = String::from("00000000-0000-0000-0000-000000000000");
    // Send a DELETE request to delete an item
    let response = app
        .oneshot(
            Request::delete(format!("/items/{}", id))
                .body(Body::empty())
                .unwrap())
        .await
        .unwrap();
    // Assert the response status is NO_CONTENT (204)
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
