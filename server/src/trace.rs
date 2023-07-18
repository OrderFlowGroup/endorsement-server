use std::time::Duration;

use axum::response::Response;
use hyper::{http::HeaderName, Request};
use tower_http::trace::{MakeSpan, OnRequest, OnResponse};
use tracing::Span;

#[derive(Clone, Debug)]
pub struct OnRequestTracingHandler;
impl<B> OnRequest<B> for OnRequestTracingHandler {
    fn on_request(&mut self, _: &hyper::Request<B>, _: &Span) {
        tracing::event!(tracing::Level::INFO, "started processing request")
    }
}

#[derive(Clone, Debug)]
pub struct OnResponseTracingHandler;
impl<B> OnResponse<B> for OnResponseTracingHandler {
    fn on_response(self, response: &Response<B>, latency: Duration, _: &Span) {
        let status = response.status().as_u16();
        if response.status().is_success() {
            tracing::event!(
                tracing::Level::INFO,
                latency = format_args!("{}μs", latency.as_micros()),
                status = %status,
                "finished processing request"
            );
        } else {
            tracing::event!(
                tracing::Level::ERROR,
                latency = format_args!("{}μs", latency.as_micros()),
                status = %status,
                "finished processing request"
            );
        }
    }
}

pub fn trace_error(msg: &str) {
    tracing::event!(
        tracing::Level::ERROR,
        msg = ?msg,
    );
}

#[derive(Clone, Debug)]
pub struct RequestSpanCreator {
    request_id_header_name: HeaderName,
}
impl RequestSpanCreator {
    pub fn new(request_id_header_name: HeaderName) -> Self {
        Self {
            request_id_header_name,
        }
    }
}
impl<B> MakeSpan<B> for RequestSpanCreator {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let id = request
            .headers()
            .get(&self.request_id_header_name)
            .map(|x| x.to_str().unwrap())
            .unwrap_or("");
        tracing::span!(
            tracing::Level::ERROR,
            "request",
            id = %id,
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
        )
    }
}
