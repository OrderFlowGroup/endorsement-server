use crate::{
    config::ServerConfig,
    endorsement::{Endorsement, EndorsementError, EndorsementParams},
    payment_in_lieu::{
        get_payment_in_lieu_approval, PaymentInLieuApproval, PaymentInLieuApprovalBody,
        PaymentInLieuApprovalError,
    },
};
use axum::{
    extract::{Json, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};
use base64::Engine as _;
use hyper::Method;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::cors::{AllowOrigin, CorsLayer};

extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::{Keypair, Signer};

#[derive(Debug)]
pub struct ServerContext {
    pub endorsement_key: Keypair,
    pub base58_endorsement_key: String,
    pub expiration_in_seconds: u8,
    pub disable_payment_in_lieu_approval: bool,
    pub server: ServerConfig,
}

pub async fn run_server(context: ServerContext) {
    let ctx = Arc::new(context);
    let server_config = ctx.server.clone();

    let host_port = format!("0.0.0.0:{}", ctx.server.port);
    log::info!("Endorsement server starting on http://{host_port}");
    log::info!("Endorsement key: {}", &ctx.base58_endorsement_key);
    log::info!("Endorsement expiration: {}", ctx.expiration_in_seconds);

    let mut app = Router::new()
        .route("/", get(|| async { "Endorsement server" }))
        .route("/health-check", get(|| async { "healthy" }))
        .route("/endorsement", get(endorsement_handler))
        .route("/endorsementKey", get(endorsement_key_handler));
    if !ctx.disable_payment_in_lieu_approval {
        app = app.route("/paymentInLieuApproval", post(payment_in_lieu_approval));
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
        log::info!("CORS origin: {}", cors_config.origin);
        layer
    });
    if cors_layer.is_some() {
        app = app.layer(cors_layer.unwrap());
    }

    axum::Server::bind(&host_port.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

pub enum AppError {
    Endorsement(EndorsementError),
    PaymentInLieuApproval(PaymentInLieuApprovalError),
}

impl From<EndorsementError> for AppError {
    fn from(inner: EndorsementError) -> Self {
        Self::Endorsement(inner)
    }
}

#[derive(Debug)]
pub enum PaymentInLieuApprovalError {
    EndorsementExpired,
    InvalidPaymentInLieuToken,
    InvalidPaymentInLieuTokenSignature,
}

impl From<PaymentInLieuApprovalError> for AppError {
    fn from(inner: PaymentInLieuApprovalError) -> Self {
        AppError::PaymentInLieuApproval(inner)
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

            AppError::PaymentInLieuApproval(PaymentInLieuApprovalError::EndorsementExpired) => {
                (StatusCode::BAD_REQUEST, "Endorsement expired")
            }
            AppError::PaymentInLieuApproval(PaymentInLieuApprovalError::InvalidPaymentInLieuToken) => {
                (StatusCode::BAD_REQUEST, "Invalid payment in lieu token")
            }
            AppError::PaymentInLieuApproval(PaymentInLieuApprovalError::InvalidPaymentInLieuTokenSignature) => {
                (StatusCode::BAD_REQUEST, "Invalid payment in lieu token signature")
            }
        };

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
    };

    let endorsement = Endorsement::new(
        &endorsement_params,
        &context.endorsement_key,
        &context.base58_endorsement_key,
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
        endorsement_key: context.base58_endorsement_key.clone(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PaymentInLieuApprovalBody {
    pub payment_in_lieu_token: PaymentInLieuToken,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PaymentInLieuToken {
    pub issuer: String,
    pub signature: String,
    pub id: String,
    pub notional: u64,
    pub auction_id: u64,
    pub auction_epoch: u64,
    pub endorsement: Endorsement,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInLieuApprovalResponse {
    pub approver: String,
    pub approval: String,
}

async fn payment_in_lieu_approval(
    Extension(context): Extension<Arc<ServerContext>>,
    Json(body): Json<PaymentInLieuApprovalBody>,
) -> Result<Json<PaymentInLieuApprovalResponse>, AppError> {
    let token = body.payment_in_lieu_token;

    // Check that endorsement is not expired
    let endorsement = token.endorsement;
    let now = seconds_since_epoch();
    if now > endorsement.expiration_time_utc {
        return Err(PaymentInLieuApprovalError::EndorsementExpired.into());
    }

    // Verify the issuer's signature of the payment in lieu message. This is needed to ensure we
    // don't sign arbitrary payloads.
    let payment_in_lieu_message = format!(
        "{},{},{},{},{}",
        token.id, token.notional, token.auction_id, token.auction_epoch, endorsement.signature,
    );
    let payment_in_lieu_message = payment_in_lieu_message.as_bytes();

    let issuer_signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&token.signature)
        .map_err(|_| PaymentInLieuApprovalError::InvalidPaymentInLieuTokenSignature)?;
    let issuer_signature = ed25519_dalek::Signature::from_bytes(&issuer_signature_bytes)
        .map_err(|_| PaymentInLieuApprovalError::InvalidPaymentInLieuTokenSignature)?;
    let issuer_public_key_bytes = bs58::decode(token.issuer.as_bytes())
        .into_vec()
        .map_err(|_| PaymentInLieuApprovalError::InvalidPaymentInLieuToken)?;
    let issuer_public_key = ed25519_dalek::PublicKey::from_bytes(&issuer_public_key_bytes)
        .map_err(|_| PaymentInLieuApprovalError::InvalidPaymentInLieuToken)?;
    if issuer_public_key
        .verify_strict(payment_in_lieu_message, &issuer_signature)
        .is_err()
    {
        return Err(PaymentInLieuApprovalError::InvalidPaymentInLieuTokenSignature.into());
    }

    // Approve the payment in lieu
    let approval_message = &issuer_signature_bytes;
    let approval_signature = context.endorsement_key.sign(approval_message);
    let approval_signature = base64::engine::general_purpose::STANDARD.encode(approval_signature);

    Ok(Json(PaymentInLieuApprovalResponse {
        approver: context.base58_endorsement_key.clone(),
        approval: approval_signature,
    }))
}

fn seconds_since_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Duration since failed")
        .as_secs()
}
