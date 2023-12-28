use anyhow::Result;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::post,
    Router,
};
use http_body_util::BodyExt;
use ring::hmac;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{debug, info, trace};

#[derive(Clone, Debug)]
struct AppState {
    hmac_verification_key: Option<hmac::Key>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // initialise tracing
    opentelemetry_tracing_utils::set_up_logging().expect("tracing setup should work");

    // set the correct hmac secret
    let hmac_verification_key =
        if let Ok(github_webhook_secret) = std::env::var("GITHUB_WEBHOOK_SECRET") {
            let hmac_verification_key =
                hmac::Key::new(hmac::HMAC_SHA256, github_webhook_secret.as_bytes());
            Some(hmac_verification_key)
        } else {
            None
        };

    let app_state = AppState {
        hmac_verification_key,
    };

    // build our application with a single route
    let app = app(app_state);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
fn app(state: AppState) -> Router {
    Router::new()
        .route("/webhook", post(post_webhook_handler))
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    webhook_secret_verification_middleware,
                ))
                .layer(TraceLayer::new_for_http()),
        )
        .with_state(state)
}

#[tracing::instrument(ret, err)]
async fn post_webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<&'static str, StatusCode> {
    dbg!(&headers);

    dbg!(body);

    match headers
        .get("X-GitHub-Event")
        // .ok_or(StatusCode::BAD_REQUEST)?
        .and_then(|x| x.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?
    {
        "pull_request" | "push" => Ok("forwarded"), // false => Err(StatusCode::BAD_REQUEST),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

#[tracing::instrument(err)]
async fn webhook_secret_verification_middleware(
    State(state): State<AppState>,
    parts: axum::http::request::Parts,
    body: Body,
    next: Next,
) -> Result<Response, StatusCode> {
    // If the github secret value has been set in the config, check it
    let new_body = if let Some(ref hmac_verification_key) = state.hmac_verification_key {
        let body_bytes = body.collect().await.unwrap().to_bytes();

        trace!("{:?}", &body_bytes);

        let github_signature_str = parts
            .headers
            .get("X-Hub-Signature-256")
            .and_then(|x| x.to_str().ok())
            .and_then(|x| x.strip_prefix("sha256="))
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // The signature has to be decoded from hexadecimal into bytes.
        let github_signature =
            hex::decode(github_signature_str).map_err(|_| StatusCode::UNAUTHORIZED)?;

        debug!(
            ?hmac_verification_key,
            github_signature_str,
            ?github_signature,
            "hmac verification"
        );

        hmac::verify(hmac_verification_key, &body_bytes, &github_signature)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        Body::from(body_bytes)
    } else {
        body
    };

    info!("hmac verification completed successfully");

    // reconstruct a request from the parts and the body
    let new_request = Request::from_parts(parts, new_body);

    Ok(next.run(new_request).await)
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use super::*;

    // make test logs show up on the console
    use test_log::test;

    #[test(tokio::test)]
    async fn pull_request_synchronised() {
        // https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#testing-the-webhook-payload-validation
        let github_webhook_secret = "It's a Secret to Everybody";
        let app_state = AppState {
            hmac_verification_key: Some(hmac::Key::new(
                hmac::HMAC_SHA256,
                github_webhook_secret.as_bytes(),
            )),
        };

        let body_content = "Hello, World!";
        dbg!(body_content.as_bytes());
        let request_body = Body::from(body_content);
        let signature_tag = hmac::sign(
            &app_state.hmac_verification_key.clone().unwrap(),
            body_content.as_bytes(),
        );

        println!("{signature_tag:?}");

        let signature_tag = signature_tag.as_ref();

        use std::fmt::Write;
        let mut signature_string = "sha256=".to_owned();
        for i in signature_tag {
            write!(signature_string, "{:02x}", i).unwrap();
        }

        dbg!(&signature_string);

        let z = app_state.hmac_verification_key.clone().unwrap();
        dbg!(z);

        let app = app(app_state);
        // `Router` implements `tower::Service<Request<Body>>` so we can
        // call it like any tower service, no need to run an HTTP server.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/webhook")
                    .method("POST")
                    .header("X-GitHub-Event", "pull_request")
                    .header("X-Hub-Signature-256", signature_string)
                    .body(request_body)
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
