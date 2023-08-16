use crate::{
    config::ServerConfig,
    trace::{trace_error, OnRequestTracingHandler, OnResponseTracingHandler, RequestSpanCreator},
};
use axum::{
    extract::{Json, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};
use hyper::{http::HeaderName, Method};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use signatory_client_lib::{
    endorsement::{Endorsement, EndorsementError, EndorsementParams},
    endorsement_key::EndorsementKey,
    payment_in_lieu::{ApprovalError, PaymentInLieuApproval, PaymentInLieuToken, VerifyTokenError},
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

extern crate rand;

#[derive(Debug)]
pub struct ServerContext {
    pub endorsement_key: EndorsementKey,
    pub expiration_in_seconds: u8,
    pub disable_payment_in_lieu_approval: bool,
    pub server: ServerConfig,
}

pub async fn run_server(context: ServerContext) {
    let ctx = Arc::new(context);
    let server_config = ctx.server.clone();

    let host_port = format!("0.0.0.0:{}", ctx.server.port);
    tracing::info!("Endorsement server starting on http://{host_port}");
    tracing::info!(
        "Endorsement key: {}",
        &ctx.endorsement_key.base58_public_key
    );
    tracing::info!("Endorsement expiration: {}", ctx.expiration_in_seconds);

    let mut app = Router::new()
        .route("/", get(|| async { "Endorsement server" }))
        .route("/health-check", get(|| async { "healthy" }))
        .route("/endorsement", get(endorsement_handler))
        .route("/endorsementKey", get(endorsement_key_handler));
    if !ctx.disable_payment_in_lieu_approval {
        app = app.route(
            "/paymentInLieuApproval",
            post(payment_in_lieu_approval_handler),
        );
    }
    app = app.layer(Extension(ctx));

    let cors_layer = server_config.cors.map(|cors_config| {
        let allowed_methods = [Method::GET, Method::POST];
        let layer = if cors_config.origin == "*" {
            CorsLayer::new()
                .allow_methods(allowed_methods)
                .allow_origin(AllowOrigin::any())
        } else {
            let parsed_origin = cors_config
                .origin
                .parse()
                .unwrap_or_else(|_| panic!("Invalid CORS origin {}", cors_config.origin));
            CorsLayer::new()
                .allow_methods(allowed_methods)
                .allow_origin([parsed_origin])
        };
        tracing::info!("CORS origin: {}", cors_config.origin);
        layer
    });
    if cors_layer.is_some() {
        app = app.layer(cors_layer.unwrap());
    }

    let x_request_id = HeaderName::from_static("x-request-id");
    app = app
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(RequestSpanCreator::new(x_request_id.clone()))
                .on_request(OnRequestTracingHandler)
                .on_response(OnResponseTracingHandler),
        )
        .layer(PropagateRequestIdLayer::new(x_request_id.clone()))
        .layer(SetRequestIdLayer::new(x_request_id, MakeRequestUuid));

    axum::Server::bind(&host_port.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppError {
    Endorsement(EndorsementError),
    PaymentInLieuApproval(ApprovalError),
}

impl From<EndorsementError> for AppError {
    fn from(inner: EndorsementError) -> Self {
        Self::Endorsement(inner)
    }
}

impl From<ApprovalError> for AppError {
    fn from(inner: ApprovalError) -> Self {
        Self::PaymentInLieuApproval(inner)
    }
}

impl IntoResponse for AppError {
    #[rustfmt::skip]
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            Self::Endorsement(EndorsementError::InvalidPlatformFeeBps) => {
                (StatusCode::BAD_REQUEST, "Invalid platformFeeBps")
            }
            Self::Endorsement(EndorsementError::PlatformFeeBpsTooHigh) => {
                (StatusCode::BAD_REQUEST, "platformFeeBps too high")
            }
            Self::Endorsement(EndorsementError::PlatformFeeBpsNotSpecified) => {
                (StatusCode::BAD_REQUEST, "platformFeeBps not specified")
            }
            Self::Endorsement(EndorsementError::PlatformFeeReceiverNotSpecified) => {
                (StatusCode::BAD_REQUEST, "platformFeeReceiver not specified")
            }
            Self::Endorsement(EndorsementError::SendQtyAndMaxSendQtySpecified) => {
                (StatusCode::BAD_REQUEST, "Request cannot specify both sendQty and maxSendQty")
            }
            Self::Endorsement(EndorsementError::SendQtyRequiresSendToken) => {
                (StatusCode::BAD_REQUEST, "sendToken must be specified if sendQty is specified")
            }
            Self::Endorsement(EndorsementError::MaxSendQtyRequiresSendToken) => {
                (StatusCode::BAD_REQUEST, "sendToken must be specified if maxSendQty is specified")
            }
            Self::Endorsement(EndorsementError::InvalidSendQty) => {
                (StatusCode::BAD_REQUEST, "Invalid sendQty")
            }
            Self::Endorsement(EndorsementError::InvalidMaxSendQty) => {
                (StatusCode::BAD_REQUEST, "Invalid maxSendQty")
            }
            Self::Endorsement(EndorsementError::InvalidAdditionalDataLength) => {
                (StatusCode::BAD_REQUEST, "additionalData too long")
            }
            Self::Endorsement(EndorsementError::InvalidAdditionalDataChar) => {
                (StatusCode::BAD_REQUEST, "additionalData contains an invalid character")
            }

            Self::PaymentInLieuApproval(ApprovalError::EndorsementExpired) => {
                (StatusCode::BAD_REQUEST, "Endorsement expired")
            }
            Self::PaymentInLieuApproval(ApprovalError::InvalidToken(VerifyTokenError::InvalidSignatureEncoding)) => {
                (StatusCode::BAD_REQUEST, "Invalid payment in lieu token signature encoding")
            }
            Self::PaymentInLieuApproval(ApprovalError::InvalidToken(VerifyTokenError::InvalidSignatureBytes)) => {
                (StatusCode::BAD_REQUEST, "Invalid payment in lieu token signature bytes")
            }
            Self::PaymentInLieuApproval(ApprovalError::InvalidToken(VerifyTokenError::InvalidIssuerEncoding)) => {
                (StatusCode::BAD_REQUEST, "Invalid payment in lieu token issuer encoding")
            }
            Self::PaymentInLieuApproval(ApprovalError::InvalidToken(VerifyTokenError::InvalidIssuerBytes)) => {
                (StatusCode::BAD_REQUEST, "Invalid payment in lieu token issuer bytes")
            }
            Self::PaymentInLieuApproval(ApprovalError::InvalidToken(VerifyTokenError::VerificationFailed)) => {
                (StatusCode::BAD_REQUEST, "Payment in lieu token signature verification failed")
            }
        };

        trace_error(msg);

        let body = Json(ErrorResponse {
            msg: String::from(msg),
        });
        (status, body).into_response()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub msg: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndorsementRequestParams {
    pub retail_trader: Option<String>,
    pub platform_fee_bps: Option<String>,
    pub platform_fee_receiver: Option<String>,
    pub send_token: Option<String>,
    pub receive_token: Option<String>,
    pub send_qty: Option<String>,
    pub max_send_qty: Option<String>,
    pub additional_data: Option<String>,
}

type EndorsementResponse = Endorsement;

async fn endorsement_handler(
    Query(params): Query<EndorsementRequestParams>,
    Extension(context): Extension<Arc<ServerContext>>,
) -> Result<Json<EndorsementResponse>, AppError> {
    let id = thread_rng().gen::<u64>();
    let now = seconds_since_epoch();
    let expiration_time_utc = now + context.expiration_in_seconds as u64;

    let endorsement_params = EndorsementParams {
        retail_trader: params.retail_trader.as_deref(),
        platform_fee_bps: params.platform_fee_bps.as_deref(),
        platform_fee_receiver: params.platform_fee_receiver.as_deref(),
        send_token: params.send_token.as_deref(),
        receive_token: params.receive_token.as_deref(),
        send_qty: params.send_qty.as_deref(),
        max_send_qty: params.max_send_qty.as_deref(),
        additional_data: params.additional_data.as_deref(),
    };

    let endorsement = Endorsement::new(
        &endorsement_params,
        &context.endorsement_key,
        expiration_time_utc,
        id,
    )?;

    Ok(Json(endorsement))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EndorsementKeyResponse {
    endorsement_key: String,
}

async fn endorsement_key_handler(
    Extension(context): Extension<Arc<ServerContext>>,
) -> Result<Json<EndorsementKeyResponse>, AppError> {
    Ok(Json(EndorsementKeyResponse {
        endorsement_key: context.endorsement_key.base58_public_key.clone(),
    }))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInLieuApprovalBody {
    pub payment_in_lieu_token: PaymentInLieuToken,
}

async fn payment_in_lieu_approval_handler(
    Extension(context): Extension<Arc<ServerContext>>,
    Json(body): Json<PaymentInLieuApprovalBody>,
) -> Result<Json<PaymentInLieuApproval>, AppError> {
    let now = seconds_since_epoch();

    let approval = body
        .payment_in_lieu_token
        .approve(&context.endorsement_key, now)?;

    Ok(Json(approval))
}

fn seconds_since_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
