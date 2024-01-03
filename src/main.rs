use std::default;

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
use futures::StreamExt;
use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use opentelemetry_tracing_utils::{OpenTelemetrySpanExt, TracingLayer, TracingService};
use ring::hmac;
use serde_json::json;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_http::trace::TraceLayer;
use tracing::{debug, debug_span, info, trace, Instrument};

#[derive(Clone, Debug)]
struct AppState {
    hmac_verification_key: Option<hmac::Key>,
    proxy_destinations: Vec<String>,
    client: TracingService<Client<HttpConnector, http_body_util::Full<Bytes>>>,
}

impl Default for AppState {
    fn default() -> Self {
        let hyper_client =
            Client::builder(TokioExecutor::new()).build_http::<http_body_util::Full<Bytes>>();

        let tower_service_stack = ServiceBuilder::new()
            .layer(TracingLayer)
            .service(hyper_client);

        let hyper_wrapped_client = futures::executor::block_on(tower_service_stack.clone().ready())
            .expect("should be valid")
            .to_owned();

        Self {
            hmac_verification_key: default::Default::default(),
            proxy_destinations: default::Default::default(),
            client: hyper_wrapped_client,
        }
    }
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

    info!("starting up");

    let app_state = AppState {
        hmac_verification_key,
        proxy_destinations: vec![
            "http://httpbin.org/anything/put_anything".to_owned(),
            "http://httpbin.org/any".to_owned(),
        ],
        ..Default::default()
    };

    // build our application with a single route
    let app = app(app_state);

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    opentelemetry_tracing_utils::shutdown_tracer_provider();

    Ok(())
}

#[tracing::instrument(ret)]
fn app(state: AppState) -> Router {
    info!("creating router");
    Router::new()
        .route("/webhook", post(post_webhook_handler))
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    webhook_secret_verification_middleware,
                ))
                // tower_http trace logging
                .layer(TraceLayer::new_for_http())
                .map_request(opentelemetry_tracing_utils::extract_trace_context),
        )
        .with_state(state)
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ResponseJsonPayload {
    message: String,
    responses: Vec<IndividualWebhookResponse>,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct IndividualWebhookResponse {
    source: String,
    status: u16,
    body: serde_json::Value,
}

#[tracing::instrument(ret, err, skip(state, parts, body))]
async fn post_webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    parts: axum::http::request::Parts,
    body: Body,
    // body: String,
) -> Result<axum::Json<ResponseJsonPayload>, StatusCode> {
    debug!("{:?}", &headers);

    debug!(
        "current trace context: {:#?}",
        tracing::Span::current().context()
    );

    match headers
        .get("X-GitHub-Event")
        // .ok_or(StatusCode::BAD_REQUEST)?
        .and_then(|x| x.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?
    {
        "pull_request" | "push" => {
            info!("forwarding");

            let body_bytes = body.collect().await.unwrap().to_bytes();

            debug!(
                "current trace context: {:#?}",
                tracing::Span::current().context()
            );

            let webhook_responses: Vec<_> = state
                .proxy_destinations
                .iter()
                .map(|destination| {
                    let mut new_parts = parts.clone();
                    new_parts.uri = http::Uri::try_from(destination).unwrap();

                    let request = hyper::Request::from_parts(new_parts, body_bytes.clone().into());

                    let response_future = state.client.clone().call(request);

                    async {
                        let response = response_future.await.unwrap();

                        let (parts, incoming_body) = response.into_parts();

                        let status = parts.status;

                        let body = incoming_body.collect().await.unwrap().to_bytes();
                        let json = serde_json::from_slice::<serde_json::Value>(&body)
                            .unwrap_or_else(|_| {
                                let body_processed = String::from_utf8_lossy(&body);
                                json!(body_processed)
                            });

                        debug!(?status, "{:?}", &json);

                        IndividualWebhookResponse {
                            body: json,
                            source: destination.to_owned(),
                            status: status.as_u16(),
                        }
                    }
                    .instrument(debug_span!("async block"))
                })
                .collect::<futures::stream::FuturesUnordered<_>>()
                .collect()
                .instrument(debug_span!("forwarding webhook"))
                .await;

            let response_json = axum::Json(ResponseJsonPayload {
                message: "webhook forwarded".to_owned(),
                responses: webhook_responses,
            });

            info!("{:#?}", &response_json);

            Ok(response_json)
        }

        _ => Err(StatusCode::BAD_REQUEST),
    }
}

#[tracing::instrument(err, skip_all)]
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
    use std::str::FromStr;

    use axum::{body::Body, http::Request};
    use serde_json::json;
    use tower::ServiceExt;
    use wiremock::{
        matchers::{self, method},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;

    // make test logs show up on the console
    // use test_log::test;

    // #[test(tokio::test)]
    #[tokio::test]
    async fn pull_request_synchronised() {
        opentelemetry_tracing_utils::set_up_logging().unwrap();

        // https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries#testing-the-webhook-payload-validation
        // Payloads, secret and signatures from GitHub page on validation
        let github_webhook_secret = "It's a Secret to Everybody";
        let body_content = "Hello, World!";
        let request_body = Body::from(body_content);

        // Start a background mock HTTP server on a random local port
        let mock_server = MockServer::start().await;

        // Arrange the behaviour of the MockServer adding a Mock:
        // when it receives a GET request on '/hello' it will respond with a 200.
        Mock::given(method("POST"))
            .and(matchers::path("/webhook"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "stuff stuff stuff",
                "webhook_data_1": "webhook info info info"
            })))
            .expect(1)
            // We assign a name to the mock - it will be shown in error messages
            // if our expectation is not verified!
            .named("webhook 1")
            // Mounting the mock on the mock server - it's now effective!
            .mount(&mock_server)
            .await;

        let app_state = AppState {
            hmac_verification_key: Some(hmac::Key::new(
                hmac::HMAC_SHA256,
                github_webhook_secret.as_bytes(),
            )),
            proxy_destinations: vec![format!("{}/webhook", mock_server.uri())],
            ..Default::default()
        };

        let app = app(app_state);
        // `Router` implements `tower::Service<Request<Body>>` so we can
        // call it like any tower service, no need to run an HTTP server.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/webhook")
                    .method("POST")
                    .header("X-GitHub-Event", "pull_request")
                    .header(
                        "X-Hub-Signature-256",
                        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
                    )
                    .body(request_body)
                    .unwrap(),
            )
            .await
            .unwrap();

        let (parts, body) = response.into_parts();
        let body_string: String = String::from_utf8(
            axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        debug!("{:?}", &parts);
        let body_json = serde_json::Value::from_str(&body_string);
        debug!("{:?}", &body_string);
        debug!("{:?}", &body_json);

        assert_eq!(parts.status, StatusCode::OK);
        assert!(body_string.contains("forwarded"));
        assert!(body_string.contains("webhook info info info"));
    }
}
