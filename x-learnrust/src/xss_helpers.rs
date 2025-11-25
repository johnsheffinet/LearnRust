/*
use axum::{
    extract::Form,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use ammonia::clean;
use askama::Template;
use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tower_http::services::ServeDir;

// A simple struct to hold comment data.
// In a real application, this would likely be stored in a database.
#[derive(Clone)]
struct Comment {
    author: String,
    content: String,
}

// Struct to deserialize the form data.
#[derive(Deserialize)]
struct CommentForm {
    author: String,
    content: String,
}

// The Askama template for rendering the comments page.
#[derive(Template)]
#[template(path = "comments.html")]
struct CommentsTemplate {
    comments: Vec<Comment>,
}

#[tokio::main]
async fn main() {
    // Shared state to store comments (using Arc<Mutex<...>> for thread safety).
    let comments = Arc::new(Mutex::new(Vec::<Comment>::new()));

    // Build the Axum application router.
    let app = Router::new()
        .route("/", get(comments_handler))
        .route("/add_comment", post(add_comment_handler))
        .nest_service("/static", ServeDir::new("static")) // Serve static files like CSS
        .with_state(comments);

    // Run the server.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

// Handler for the main page, displaying existing comments.
async fn comments_handler(
    // Extract the shared state.
    axum::extract::State(comments): axum::extract::State<Arc<Mutex<Vec<Comment>>>>,
) -> impl IntoResponse {
    let comments_lock = comments.lock().unwrap();
    let template = CommentsTemplate {
        comments: comments_lock.clone(),
    };
    Html(template.render().unwrap())
}

// Handler for adding new comments.
async fn add_comment_handler(
    axum::extract::State(comments): axum::extract::State<Arc<Mutex<Vec<Comment>>>>,
    Form(form): Form<CommentForm>,
) -> impl IntoResponse {
    // **XSS PREVENTION:**
    // Sanitize the user input using ammonia::clean().
    // Ammonia uses a whitelist approach, removing dangerous tags and attributes.
    let sanitized_content = clean(&form.content);
    
    // For the author name, if we only expect plain text, we might want to 
    // restrict it further or simply escape it using the templating engine's 
    // automatic escaping features (Askama does this by default).
    // Here we assume Askama handles the author name escaping in the template.

    let new_comment = Comment {
        author: form.author,
        content: sanitized_content,
    };

    let mut comments_lock = comments.lock().unwrap();
    comments_lock.push(new_comment);

    // Redirect back to the main page to see the new comment.
    axum::response::Redirect::to("/")
}
 */
