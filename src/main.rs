use anyhow::Result;
use axum::{
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // initialise tracing
    opentelemetry_tracing_utils::set_up_logging().expect("tracing setup should work");

    // build our application with a single route
    let app = app();

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
fn app() -> Router {
    Router::new().route("/webhook", post(post_webhook_handler))
}

#[tracing::instrument(ret, err)]
async fn post_webhook_handler(
    headers: HeaderMap,
    body: String,
) -> Result<&'static str, StatusCode> {
    let webhook_is_validated = true;

    dbg!(&headers);

    dbg!(body);

    if !webhook_is_validated {
        return Err(StatusCode::BAD_REQUEST);
    };

    info!("validated webhook");

    match headers
        .get("X-GitHub-Event")
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?
    {
        "pull_request" | "push" => Ok("forwarded"), // false => Err(StatusCode::BAD_REQUEST),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn pull_request_synchronised() {
        let app = app();

        // `Router` implements `tower::Service<Request<Body>>` so we can
        // call it like any tower service, no need to run an HTTP server.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/webhook")
                    .method("POST")
                    .header("X-GitHub-Event", "pull_request")
                    .body(Body::from("{a: 5, e: 20}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let (parts, body) = response.into_parts();

        let body_string: String = String::from_utf8(
            axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        dbg!(parts);
        dbg!(&body_string);

        assert!(body_string.contains("forwarded"));
    }
}
