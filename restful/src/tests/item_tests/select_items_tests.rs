use super::*;

#[tokio::test]
async fn test_select_items_ok() {
    // Create an instance of the app with a shared database
    let app = app_with_db();
    // Create a payload for the create_item request
    let payload = json!({"name" : "select_items", "value" : "ok"});
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
    // Send a GET request to select items with the same name and value         
    let response = app
        .oneshot(
            Request::get(format!("/items?name={}&value={}", payload["name"].as_str().unwrap(), payload["value"].as_str().unwrap()))
                .body(Body::empty())
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
    // Assert the response body contains the requested items
    assert!(body.is_array());
    assert!(body[0].get("id").is_some());
    assert_eq!(body[0]["name"], payload["name"]);
    assert_eq!(body[0]["value"], payload["value"]);
}

#[tokio::test]
async fn test_select_items_unprocessable_entity() {
    // Create an instance of the app with a shared database
    let app = app_with_db();
    // Create query parameters for the select_items request
    let parameters = json!({"name" : "", "value" : ""});
    // Send a GET request with the name and value query parameters to select items
    let response = app
        .oneshot(
            Request::get(format!("/items?name={}&value={}", parameters["name"].as_str().unwrap(), parameters["value"].as_str().unwrap()))
                .body(Body::empty())
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
    // Assert the response body contains the requested items
    assert!(body.get("errors").is_some());
}
