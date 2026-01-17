use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    body: String,
}

#[derive(Serialize)]
struct Response {
    #[serde(rename = "statusCode")]
    status_code: i32,
    body: String,
}

async fn function_handler(event: LambdaEvent<Request>) -> Result<Response, Error> {
    let body = event.payload.body;

    let response = Response {
        status_code: 200,
        body: format!("Hello from Rust Lambda! Input: {}", body),
    };

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(function_handler)).await
}
