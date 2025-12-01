/*
use validator::Validate;
use serde::Deserialize;

// This struct defines the rules for valid user input.
#[derive(Debug, Validate, Deserialize)]
struct UserInput {
    // Ensure the username is between 2 and 50 characters long.
    #[validate(length(min = 2, max = 50, message = "Username must be between 2 and 50 characters"))]
    // Ensure the username only contains alphanumeric characters.
    #[validate(regex(path = "ALPHANUMERIC_REGEX", message = "Username can only contain letters and numbers"))]
    username: String,

    // Ensure the email is a valid email format.
    #[validate(email(message = "Invalid email address"))]
    email: String,

    // Ensure the age is within a specific range.
    #[validate(range(min = 18, max = 120, message = "Must be 18 years or older"))]
    age: u8,

    // Validate a nested struct or list of structs
    #[validate] 
    address: Address,
}

#[derive(Debug, Validate, Deserialize)]
struct Address {
    #[validate(length(min = 5, message = "Zip code too short"))]
    zip_code: String,
}

// A static regex is needed for the regex validator
static ALPHANUMERIC_REGEX: once_cell::sync::Lazy<regex::Regex> = 
    once_cell::sync::Lazy::new(|| regex::Regex::new(r"^[a-zA-Z0-9]+$").unwrap());
fn process_user_input(input: UserInput) {
    match input.validate() {
        Ok(()) => {
            println!("Input is valid: {:?}", input);
            // Proceed with business logic
        }
        Err(errors) => {
            eprintln!("Validation failed with errors:");
            for (field, field_errors) in errors.field_errors() {
                eprintln!("- Field: {}", field);
                for err in field_errors {
                    eprintln!("  - Error: {:?}", err.code);
                    if let Some(msg) = err.message.as_ref() {
                         eprintln!("    Message: {}", msg);
                    }
                }
            }
        }
    }
}

// Example usage:
fn main() {
    // Valid input
    let valid_user = UserInput {
        username: "johndoe123".to_string(),
        email: "john@example.com".to_string(),
        age: 30,
        address: Address { zip_code: "12345".to_string() },
    };
    process_user_input(valid_user);

    println!("---");

    // Invalid input
    let invalid_user = UserInput {
        username: "!!invalid!!".to_string(), // Fails regex
        email: "not-an-email".to_string(),  // Fails email
        age: 15,                             // Fails range
        address: Address { zip_code: "123".to_string() }, // Fails length
    };
    process_user_input(invalid_user);
}

// Requires the 'axum-valid' crate
use axum::{extract::Form, routing::post, Router};
use axum_valid::Valid;

// ... (UserInput struct definition as above) ...

async fn handle_submission(
    // Axum uses 'Valid<Form<T>>' or 'Valid<Json<T>>' to automatically validate
    // the input. If validation fails, it returns a 400 Bad Request error.
    Valid(Form(input)): Valid<Form<UserInput>>,
) -> String {
    format!("Welcome, {}!", input.username)
}

// Router setup:
// let app = Router::new().route("/submit", post(handle_submission));
 */