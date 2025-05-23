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
use http::{HeaderName, HeaderValue};
use http_body_util::BodyExt;
use opentelemetry_tracing_utils::{make_tower_http_otel_trace_layer, OpenTelemetrySpanExt};
use ring::hmac;
use serde_json::json;
use tower::ServiceBuilder;
use tracing::{debug, debug_span, info, info_span, trace, warn, Instrument};

#[derive(Clone, Debug)]
struct AppState {
    hmac_verification_key: Option<hmac::Key>,
    proxy_destinations: Vec<String>,
    headers_that_should_be_forwarded: Vec<String>,
    reqwest_client: reqwest_middleware::ClientWithMiddleware,
}

impl Default for AppState {
    fn default() -> Self {
        let reqwest_client_without_middleware = reqwest::Client::new();

        let reqwest_client =
            reqwest_middleware::ClientBuilder::new(reqwest_client_without_middleware)
                .with(reqwest_tracing::TracingMiddleware::default())
                .build();

        // Headers that GitHub webhooks include
        // Could make this configurable using figment or something similar at some point
        let headers_that_should_be_forwarded = [
            "Accept",
            "Content-Type",
            "User-Agent",
            "X-GitHub-Delivery",
            "X-GitHub-Event",
            "X-GitHub-Hook-ID",
            "X-GitHub-Hook-Installation-Target-ID",
            "X-GitHub-Hook-Installation-Target-Type",
        ]
        .map(String::from)
        .to_vec();

        Self {
            hmac_verification_key: default::Default::default(),
            proxy_destinations: default::Default::default(),
            headers_that_should_be_forwarded,
            reqwest_client,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // initialise tracing
    opentelemetry_tracing_utils::set_up_logging().expect("tracing setup should work");

    let app = info_span!("Initialising").in_scope(|| {
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

        // Get the destinations to forward webhooks to
        let proxy_destinations: Vec<String> = std::env::var("PROXY_DESTINATIONS").map_or_else(
            |error_var| {
                warn!("PROXY_DESTINATIONS env var not set, using default config");
                warn!("{}", error_var);

                vec![
                    "http://argocd-server.argocd:443/api/webhook".to_owned(),
                    "http://argocd-applicationset-controller.argocd:7000/api/webhook".to_owned(),
                    "http://kubechecks.kubechecks:8080/hooks/github/project".to_owned(),
                ]
            },
            |var_value| var_value.split(',').map(|s| s.to_owned()).collect(),
        );

        info!("proxy destinations: {:?}", &proxy_destinations);

        let reqwest_client_without_middleware = reqwest::Client::builder().build().unwrap();
        let reqwest_client =
            reqwest_middleware::ClientBuilder::new(reqwest_client_without_middleware)
                .with(reqwest_tracing::TracingMiddleware::default())
                .build();

        let app_state = AppState {
            hmac_verification_key,
            proxy_destinations,
            reqwest_client,
            ..Default::default()
        };

        // build our application with a single route
        app(app_state)
    });

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
        .route("/api/webhook", post(post_webhook_handler))
        .layer(
            ServiceBuilder::new()
                // .map_request(opentelemetry_tracing_utils::extract_trace_context)
                // tower_http trace logging
                .layer(make_tower_http_otel_trace_layer())
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    webhook_secret_verification_middleware,
                )),
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
    debug!(
        "current trace context: {:#?}",
        tracing::Span::current().context()
    );

    match headers
        .get("X-GitHub-Event")
        .and_then(|x| x.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?
    {
        "pull_request" | "push" => {
            info!("forwarding");

            let body_bytes = body.collect().await.unwrap().to_bytes();

            // a new headermap filtered to contain just the headers that I actually want to forward
            let mut headermap_to_forward = HeaderMap::new();
            for i in state.headers_that_should_be_forwarded {
                parts.headers.get(&i).map(|header_value| {
                    headermap_to_forward.insert(
                        HeaderName::try_from(i).expect(
                            "HeaderValue from the list of headers to forward should be valid",
                        ),
                        header_value.clone(),
                    )
                });
            }

            debug!(
                "headermap that will be forwarded: {:#?}",
                headermap_to_forward
            );

            let webhook_responses: Vec<_> = state
                .proxy_destinations
                .iter()
                .map(|destination| {
                    send_one_forwarded_request_and_parse_response(
                        destination,
                        &state.reqwest_client,
                        &body_bytes,
                        parts.method.clone(),
                        headermap_to_forward.clone(),
                    )
                })
                .collect::<futures::stream::FuturesUnordered<_>>()
                .collect()
                .instrument(debug_span!("forwarding webhooks"))
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

#[tracing::instrument]
async fn send_one_forwarded_request_and_parse_response(
    new_destination_url: &str,
    reqwest_client: &reqwest_middleware::ClientWithMiddleware,
    body_bytes: &axum::body::Bytes,
    method: http::Method,
    forwarded_headers: HeaderMap<HeaderValue>,
) -> IndividualWebhookResponse {
    let reqwest_request = reqwest_client
        .request(
            method,
            reqwest::Url::parse(new_destination_url).expect("should be valid url"),
        )
        .headers(forwarded_headers)
        .body(body_bytes.clone());

    let reqwest_response = reqwest_request.send().await.expect("request should work");
    let status = reqwest_response.status();
    let reqwest_body_string = reqwest_response
        .text()
        .await
        .expect("expect valid bytes from the response");

    let json =
        serde_json::from_str(&reqwest_body_string).unwrap_or_else(|_| json!(reqwest_body_string));

    debug!(?status, new_destination_url, returned_body = ?json, "webhook forwarded to {}", new_destination_url);

    IndividualWebhookResponse {
        body: json,
        source: new_destination_url.to_owned(),
        status: status.as_u16(),
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

        // Add a mock to ensure correct behaviour given a redirect
        Mock::given(method("POST"))
            .and(matchers::path("/webhook-with-redirect"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", "/webhook-redirected-destination"),
            )
            .expect(1)
            // We assign a name to the mock - it will be shown in error messages
            // if our expectation is not verified!
            .named("webhook redirect")
            // Mounting the mock on the mock server - it's now effective!
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(matchers::path("/webhook-redirected-destination"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": "this is the result of the redirect!",
                "webhook_data_1": "webhook info info info"
            })))
            .expect(1)
            // We assign a name to the mock - it will be shown in error messages
            // if our expectation is not verified!
            .named("webhook redirected destination")
            // Mounting the mock on the mock server - it's now effective!
            .mount(&mock_server)
            .await;

        let app_state = AppState {
            hmac_verification_key: Some(hmac::Key::new(
                hmac::HMAC_SHA256,
                github_webhook_secret.as_bytes(),
            )),
            proxy_destinations: vec![
                format!("{}/webhook", mock_server.uri()),
                format!("{}/webhook-with-redirect", mock_server.uri()),
            ],
            ..Default::default()
        };

        let app = app(app_state);
        // `Router` implements `tower::Service<Request<Body>>` so we can
        // call it like any tower service, no need to run an HTTP server.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/webhook")
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
