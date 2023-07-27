use base64::Engine as _;
use ed25519_dalek::{Keypair, Signer};
use serde::{Deserialize, Serialize};

use crate::endorsement::Endorsement;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInLieuToken {
    pub issuer: String,
    pub signature: String,
    pub id: String,
    pub notional: u64,
    pub auction_id: u64,
    pub auction_epoch: u64,
    pub endorsement: Endorsement,
}

impl PaymentInLieuToken {
    #[allow(dead_code)]
    /// Create a payment in lieu token signed by the issuer.
    pub fn new(params: &CreatePaymentInLieuTokenParams) -> Self {
        let msg = Self::make_payment_in_lieu_msg(MakePaymentInLieuMsgParams {
            id: params.id,
            notional: params.notional,
            auction_id: params.auction_id,
            auction_epoch: params.auction_epoch,
            endorsement: params.endorsement,
        });
        let sig = params.issuer.sign(&msg);
        let encoded_sig = Self::encode_signature(&sig);
        Self {
            issuer: params.issuer_base58_public_key.to_owned(),
            signature: encoded_sig,
            id: params.id.to_owned(),
            notional: params.notional,
            auction_id: params.auction_id,
            auction_epoch: params.auction_epoch,
            endorsement: params.endorsement.clone(),
        }
    }

    /// Verify the issuer's signature of the payment in lieu token. Returns the
    /// issuer's signature.
    pub fn verify(&self) -> Result<ed25519_dalek::Signature, VerifyTokenError> {
        let msg = Self::make_payment_in_lieu_msg(MakePaymentInLieuMsgParams {
            id: &self.id,
            notional: self.notional,
            auction_id: self.auction_id,
            auction_epoch: self.auction_epoch,
            endorsement: &self.endorsement,
        });
        let sig = self.decode_signature()?;
        let issuer_public_key = self.decode_issuer()?;
        issuer_public_key
            .verify_strict(&msg, &sig)
            .map_err(|_| VerifyTokenError::VerificationFailed)?;
        Ok(sig)
    }

    /// Create an approval of the token, signed by the `endorsement_key`.
    /// `base58_endorsement_key` must be specified as the Base58-encoded public
    /// key of the endorsement key.
    pub fn approve(
        &self,
        endorsement_key: &ed25519_dalek::Keypair,
        base58_endorsement_key: &str,
        now_utc_seconds: u64,
    ) -> ApprovalResult {
        // Check that endorsement is not expired
        if now_utc_seconds >= self.endorsement.expiration_time_utc {
            return Err(ApprovalError::EndorsementExpired);
        }

        // Verify the issuer's signature of the payment in lieu message. This
        // is needed to ensure we don't sign arbitrary payloads.
        let issuer_signature = self.verify().map_err(ApprovalError::InvalidToken)?;

        // Approve the payment in lieu
        let approval_message = &issuer_signature.to_bytes();
        let approval_sig = endorsement_key.sign(approval_message);
        let encoded_approval_sig = PaymentInLieuApproval::encode_approval(&approval_sig);

        Ok(PaymentInLieuApproval {
            approver: base58_endorsement_key.to_string(),
            approval: encoded_approval_sig,
        })
    }

    fn make_payment_in_lieu_msg(params: MakePaymentInLieuMsgParams) -> Vec<u8> {
        format!(
            "{},{},{},{},{}",
            params.id,
            params.notional,
            params.auction_id,
            params.auction_epoch,
            params.endorsement.signature,
        )
        .into()
    }

    fn encode_signature(signature: &ed25519_dalek::Signature) -> String {
        base64::engine::general_purpose::STANDARD.encode(signature)
    }

    fn decode_signature(&self) -> Result<ed25519_dalek::Signature, DecodeSignatureError> {
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.signature)
            .map_err(|_| DecodeSignatureError::InvalidEncoding)?;
        ed25519_dalek::Signature::from_bytes(&sig_bytes)
            .map_err(|_| DecodeSignatureError::InvalidBytes)
    }

    #[allow(dead_code)]
    /// Returns the issuer's public key as a Base58-encoded string.
    fn encode_issuer(issuer: &ed25519_dalek::PublicKey) -> String {
        bs58::encode(issuer.as_bytes()).into_string()
    }

    fn decode_issuer(&self) -> Result<ed25519_dalek::PublicKey, DecodeIssuerError> {
        let issuer_bytes = bs58::decode(&self.issuer)
            .into_vec()
            .map_err(|_| DecodeIssuerError::InvalidEncoding)?;
        ed25519_dalek::PublicKey::from_bytes(&issuer_bytes)
            .map_err(|_| DecodeIssuerError::InvalidBytes)
    }
}

pub struct CreatePaymentInLieuTokenParams<'a> {
    pub issuer: &'a Keypair,
    pub issuer_base58_public_key: &'a str,
    pub id: &'a str,
    pub notional: u64,
    pub auction_id: u64,
    pub auction_epoch: u64,
    pub endorsement: &'a Endorsement,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerifyTokenError {
    InvalidSignatureEncoding,
    InvalidSignatureBytes,
    InvalidIssuerEncoding,
    InvalidIssuerBytes,
    VerificationFailed,
}

type ApprovalResult = Result<PaymentInLieuApproval, ApprovalError>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ApprovalError {
    EndorsementExpired,
    InvalidToken(VerifyTokenError),
}

#[derive(Debug, PartialEq)]
enum DecodeSignatureError {
    InvalidEncoding,
    InvalidBytes,
}

#[derive(Debug, PartialEq)]
enum DecodeIssuerError {
    InvalidEncoding,
    InvalidBytes,
}

impl From<DecodeSignatureError> for VerifyTokenError {
    fn from(inner: DecodeSignatureError) -> Self {
        match inner {
            DecodeSignatureError::InvalidEncoding => Self::InvalidSignatureEncoding,
            DecodeSignatureError::InvalidBytes => Self::InvalidSignatureBytes,
        }
    }
}

impl From<DecodeIssuerError> for VerifyTokenError {
    fn from(inner: DecodeIssuerError) -> Self {
        match inner {
            DecodeIssuerError::InvalidEncoding => Self::InvalidIssuerEncoding,
            DecodeIssuerError::InvalidBytes => Self::InvalidIssuerBytes,
        }
    }
}

struct MakePaymentInLieuMsgParams<'a> {
    pub id: &'a str,
    pub notional: u64,
    pub auction_id: u64,
    pub auction_epoch: u64,
    pub endorsement: &'a Endorsement,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInLieuApproval {
    pub approver: String,
    pub approval: String,
}

impl PaymentInLieuApproval {
    #[allow(dead_code)]
    /// Verify the approval of the payment in lieu token.
    pub fn verify(&self, token: &PaymentInLieuToken) -> Result<(), VerifyApprovalError> {
        let msg = Self::make_payment_in_lieu_approval_msg(token)
            .ok_or(VerifyApprovalError::InvalidTokenSignature)?;
        let approval_sig = self.decode_approval()?;
        let approver_public_key = self.decode_approver()?;
        approver_public_key
            .verify_strict(&msg, &approval_sig)
            .map_err(|_| VerifyApprovalError::VerificationFailed)
    }

    fn make_payment_in_lieu_approval_msg(token: &PaymentInLieuToken) -> Option<Vec<u8>> {
        token
            .decode_signature()
            .map(|sig| Some(sig.to_bytes().into()))
            .unwrap_or(None)
    }

    fn encode_approval(approval: &ed25519_dalek::Signature) -> String {
        base64::engine::general_purpose::STANDARD.encode(approval)
    }

    fn decode_approval(&self) -> Result<ed25519_dalek::Signature, DecodeApprovalError> {
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.approval)
            .map_err(|_| DecodeApprovalError::InvalidEncoding)?;
        ed25519_dalek::Signature::from_bytes(&sig_bytes)
            .map_err(|_| DecodeApprovalError::InvalidBytes)
    }

    #[allow(dead_code)]
    /// Returns the approver's public key as a Base58-encoded string.
    pub fn encode_approver(approver: &ed25519_dalek::PublicKey) -> String {
        bs58::encode(approver.as_bytes()).into_string()
    }

    fn decode_approver(&self) -> Result<ed25519_dalek::PublicKey, DecodeApproverError> {
        let approver_bytes = bs58::decode(&self.approver)
            .into_vec()
            .map_err(|_| DecodeApproverError::InvalidEncoding)?;
        ed25519_dalek::PublicKey::from_bytes(&approver_bytes)
            .map_err(|_| DecodeApproverError::InvalidBytes)
    }
}

#[derive(Debug, PartialEq)]
pub enum VerifyApprovalError {
    InvalidTokenSignature,
    InvalidApprovalEncoding,
    InvalidApprovalBytes,
    InvalidApproverEncoding,
    InvalidApproverBytes,
    VerificationFailed,
}

#[derive(Debug, PartialEq)]
enum DecodeApprovalError {
    InvalidEncoding,
    InvalidBytes,
}

#[derive(Debug, PartialEq)]
enum DecodeApproverError {
    InvalidEncoding,
    InvalidBytes,
}

impl From<DecodeApprovalError> for VerifyApprovalError {
    fn from(inner: DecodeApprovalError) -> Self {
        match inner {
            DecodeApprovalError::InvalidEncoding => Self::InvalidApprovalEncoding,
            DecodeApprovalError::InvalidBytes => Self::InvalidApprovalBytes,
        }
    }
}

impl From<DecodeApproverError> for VerifyApprovalError {
    fn from(inner: DecodeApproverError) -> Self {
        match inner {
            DecodeApproverError::InvalidEncoding => Self::InvalidApproverEncoding,
            DecodeApproverError::InvalidBytes => Self::InvalidApproverBytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endorsement::{Endorsement, EndorsementParams};

    fn get_endorsement_key() -> (Keypair, String) {
        let secret_key_bytes: &[u8] = &[
            163, 149, 135, 21, 131, 252, 66, 166, 218, 129, 77, 126, 252, 115, 128, 179, 140, 205,
            50, 134, 251, 100, 23, 49, 139, 32, 136, 154, 33, 221, 59, 160, 93, 175, 53, 246, 159,
            212, 84, 105, 99, 223, 22, 174, 67, 128, 24, 158, 93, 24, 214, 22, 228, 40, 163, 142,
            206, 34, 10, 11, 22, 111, 152, 168,
        ];
        let endorsement_key = Keypair::from_bytes(secret_key_bytes).unwrap();
        let base58_endorsement_key = Endorsement::encode_endorser(&endorsement_key.public);
        (endorsement_key, base58_endorsement_key)
    }

    fn get_issuer_key() -> (Keypair, String) {
        let secret_key_bytes: &[u8] = &[
            243, 10, 244, 250, 30, 231, 155, 23, 90, 48, 237, 145, 150, 14, 185, 27, 39, 29, 197,
            125, 24, 120, 53, 216, 83, 194, 250, 1, 126, 148, 141, 255, 152, 156, 221, 249, 129,
            22, 130, 148, 7, 149, 157, 215, 213, 186, 184, 159, 198, 95, 93, 36, 116, 212, 179,
            184, 241, 9, 27, 55, 27, 250, 48, 250,
        ];
        let issuer_key = Keypair::from_bytes(secret_key_bytes).unwrap();
        let base58_issuer_key = PaymentInLieuToken::encode_issuer(&issuer_key.public);
        (issuer_key, base58_issuer_key)
    }

    struct CallCreateTokenParams {
        id: String,
        notional: u64,
        auction_id: u64,
        auction_epoch: u64,
        endorsement: Endorsement,
    }

    fn call_create_token(params: CallCreateTokenParams) -> PaymentInLieuToken {
        let (issuer_key, base58_issuer_key) = get_issuer_key();
        PaymentInLieuToken::new(&CreatePaymentInLieuTokenParams {
            issuer: &issuer_key,
            issuer_base58_public_key: &base58_issuer_key,
            id: &params.id,
            notional: params.notional,
            auction_id: params.auction_id,
            auction_epoch: params.auction_epoch,
            endorsement: &params.endorsement,
        })
    }

    struct CreateTestEndorsementParams<'a> {
        endorsement_params: EndorsementParams<'a>,
        id: u64,
        expiration_time_utc: u64,
    }

    fn create_test_endorsement(params: CreateTestEndorsementParams) -> Endorsement {
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        Endorsement::new(
            &params.endorsement_params,
            &endorsement_key,
            &base58_endorsement_key,
            params.expiration_time_utc,
            params.id,
        )
        .unwrap()
    }

    struct CreateTestTokenParams<'a> {
        id: &'a str,
        notional: u64,
        auction_id: u64,
        auction_epoch: u64,
        endorsement_expiration_time: u64,
    }

    fn create_test_token(params: CreateTestTokenParams) -> (PaymentInLieuToken, Endorsement) {
        let endorsement = create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: EndorsementParams {
                retail_trader: Some("rt"),
                platform_fee_bps: None,
                platform_fee_receiver: None,
                send_token: None,
                receive_token: None,
                send_qty: None,
                max_send_qty: None,
                additional_data: None,
            },
            id: 0,
            expiration_time_utc: params.endorsement_expiration_time,
        });
        let token = call_create_token(CallCreateTokenParams {
            id: params.id.to_owned(),
            notional: params.notional,
            auction_id: params.auction_id,
            auction_epoch: params.auction_epoch,
            endorsement: endorsement.clone(),
        });
        (token, endorsement)
    }

    struct CreateTestToken2Params {
        endorsement_expiration_time: u64,
    }

    fn create_test_token2(params: CreateTestToken2Params) -> PaymentInLieuToken {
        create_test_token(CreateTestTokenParams {
            id: "abc",
            notional: 10000,
            auction_id: 1,
            auction_epoch: 2,
            endorsement_expiration_time: params.endorsement_expiration_time,
        })
        .0
    }

    fn create_test_token_and_approval() -> (PaymentInLieuToken, PaymentInLieuApproval) {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });
        let approval = approve(ApproveParams {
            token: token.clone(),
            now_utc_seconds: endorsement_expiration_time - 30,
        })
        .unwrap();
        (token, approval)
    }

    struct ApproveParams {
        token: PaymentInLieuToken,
        now_utc_seconds: u64,
    }

    fn approve(params: ApproveParams) -> ApprovalResult {
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        params.token.approve(
            &endorsement_key,
            &base58_endorsement_key,
            params.now_utc_seconds,
        )
    }

    struct ExpectedPaymentInLieuApproval {
        pub endorsement_key: Keypair,
        pub endorser_base58_public_key: String,
    }

    fn check_approval(
        token: &PaymentInLieuToken,
        actual: ApprovalResult,
        expected: ExpectedPaymentInLieuApproval,
    ) {
        assert!(actual.is_ok());
        let actual = actual.unwrap();

        let msg = PaymentInLieuApproval::make_payment_in_lieu_approval_msg(token).unwrap();
        let expected_approval_signature =
            PaymentInLieuApproval::encode_approval(&expected.endorsement_key.sign(&msg));

        assert_eq!(actual.approver, expected.endorser_base58_public_key);
        assert_eq!(actual.approval, expected_approval_signature);

        assert!(actual.verify(token).is_ok());
    }

    struct ExpectedPaymentInLieuToken<'a> {
        pub issuer_key: Keypair,
        pub issuer_base58_public_key: String,
        pub id: &'a str,
        pub notional: u64,
        pub auction_id: u64,
        pub auction_epoch: u64,
        pub endorsement: &'a Endorsement,
    }

    fn check_token(actual: &PaymentInLieuToken, expected: ExpectedPaymentInLieuToken) {
        let msg = PaymentInLieuToken::make_payment_in_lieu_msg(MakePaymentInLieuMsgParams {
            id: expected.id,
            notional: expected.notional,
            auction_id: expected.auction_id,
            auction_epoch: expected.auction_epoch,
            endorsement: expected.endorsement,
        });
        let expected_signature =
            PaymentInLieuToken::encode_signature(&expected.issuer_key.sign(&msg));

        assert_eq!(actual.issuer, expected.issuer_base58_public_key);
        assert_eq!(actual.signature, expected_signature);
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.notional, expected.notional);
        assert_eq!(actual.auction_id, expected.auction_id);
        assert_eq!(actual.auction_epoch, expected.auction_epoch);

        assert!(actual.verify().is_ok());
    }

    fn assert_verify_err(
        verify_result: Result<ed25519_dalek::Signature, VerifyTokenError>,
        err: VerifyTokenError,
    ) {
        assert!(verify_result.is_err());
        assert_eq!(verify_result.unwrap_err(), err);
    }

    #[test]
    fn test_create_payment_in_lieu_token() {
        let id = "abc";
        let notional = 10000;
        let auction_id = 1;
        let auction_epoch = 2;
        let endorsement_expiration_time = 1689028449;
        let (token, endorsement) = create_test_token(CreateTestTokenParams {
            id,
            notional,
            auction_id,
            auction_epoch,
            endorsement_expiration_time,
        });

        let (issuer_key, base58_issuer_key) = get_issuer_key();
        check_token(
            &token,
            ExpectedPaymentInLieuToken {
                issuer_key,
                issuer_base58_public_key: base58_issuer_key,
                id,
                notional,
                auction_id,
                auction_epoch,
                endorsement: &endorsement,
            },
        );
    }

    #[test]
    fn test_verify_token() {
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time: 1689028449,
        });
        assert!(token.verify().is_ok());
    }

    #[test]
    fn test_verify_token_err_invalid_sig_encoding() {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });
        let sig_bytes = token.decode_signature().unwrap().to_bytes();

        let utf8_sig = String::from_utf8_lossy(&sig_bytes).into_owned();
        let token_with_utf8_sig = PaymentInLieuToken {
            signature: utf8_sig,
            ..token
        };
        let verify_result = token_with_utf8_sig.verify();
        assert_verify_err(verify_result, VerifyTokenError::InvalidSignatureEncoding);
    }

    #[test]
    fn test_verify_token_err_invalid_sig_bytes() {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });
        let sig_bytes = token.decode_signature().unwrap().to_bytes();

        let invalid_sig_bytes = &sig_bytes[..sig_bytes.len() - 5];
        let invalid_sig = base64::engine::general_purpose::STANDARD.encode(invalid_sig_bytes);
        let token_with_invalid_sig_bytes = PaymentInLieuToken {
            signature: invalid_sig,
            ..token.clone()
        };
        let verify_result = token_with_invalid_sig_bytes.verify();
        assert_verify_err(verify_result, VerifyTokenError::InvalidSignatureBytes);

        let token_with_invalid_sig_bytes = PaymentInLieuToken {
            signature: "".to_owned(),
            ..token
        };
        let verify_result = token_with_invalid_sig_bytes.verify();
        assert_verify_err(verify_result, VerifyTokenError::InvalidSignatureBytes);
    }

    #[test]
    fn test_verify_token_err_invalid_issuer_encoding() {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });
        let issuer_bytes = token.decode_issuer().unwrap().to_bytes();

        let base64_issuer = base64::engine::general_purpose::STANDARD.encode(issuer_bytes);
        let token_with_base64_issuer = PaymentInLieuToken {
            issuer: base64_issuer,
            ..token
        };
        let verify_result = token_with_base64_issuer.verify();
        assert_verify_err(verify_result, VerifyTokenError::InvalidIssuerEncoding);
    }

    #[test]
    fn test_verify_token_err_invalid_issuer_bytes() {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });
        let issuer_bytes = token.decode_issuer().unwrap().to_bytes();

        let invalid_issuer_bytes = &issuer_bytes[..issuer_bytes.len() - 5];
        let invalid_issuer = bs58::encode(invalid_issuer_bytes).into_string();
        let token_with_invalid_issuer_bytes = PaymentInLieuToken {
            issuer: invalid_issuer,
            ..token.clone()
        };
        let verify_result = token_with_invalid_issuer_bytes.verify();
        assert_verify_err(verify_result, VerifyTokenError::InvalidIssuerBytes);

        let token_with_invalid_issuer_bytes = PaymentInLieuToken {
            issuer: "".to_owned(),
            ..token
        };
        let verify_result = token_with_invalid_issuer_bytes.verify();
        assert_verify_err(verify_result, VerifyTokenError::InvalidIssuerBytes);
    }

    #[test]
    fn test_verify_token_err_verification_failed() {
        let id = "abc";
        let notional = 10000;
        let auction_id = 1;
        let auction_epoch = 2;
        let endorsement_expiration_time = 1689028449;
        let (token, _) = create_test_token(CreateTestTokenParams {
            id,
            notional,
            auction_id,
            auction_epoch,
            endorsement_expiration_time,
        });

        let changed_id = id.to_owned() + "abc";
        let token_with_changed_id = PaymentInLieuToken {
            id: changed_id,
            ..token.clone()
        };
        let verify_result = token_with_changed_id.verify();
        assert_verify_err(verify_result, VerifyTokenError::VerificationFailed);

        let changed_notional = notional - 1;
        let token_with_changed_notional = PaymentInLieuToken {
            notional: changed_notional,
            ..token.clone()
        };
        let verify_result = token_with_changed_notional.verify();
        assert_verify_err(verify_result, VerifyTokenError::VerificationFailed);

        let changed_auction_id = auction_id + 1;
        let token_with_changed_auction_id = PaymentInLieuToken {
            auction_id: changed_auction_id,
            ..token.clone()
        };
        let verify_result = token_with_changed_auction_id.verify();
        assert_verify_err(verify_result, VerifyTokenError::VerificationFailed);

        let changed_auction_epoch = auction_epoch + 1;
        let token_with_changed_auction_epoch = PaymentInLieuToken {
            auction_epoch: changed_auction_epoch,
            ..token.clone()
        };
        let verify_result = token_with_changed_auction_epoch.verify();
        assert_verify_err(verify_result, VerifyTokenError::VerificationFailed);

        let endorsement_with_changed_sig = Endorsement {
            signature: token.endorsement.signature.to_owned() + "abc",
            ..token.endorsement.clone()
        };
        let token_with_changed_endorsement_sig = PaymentInLieuToken {
            endorsement: endorsement_with_changed_sig,
            ..token.clone()
        };
        let verify_result = token_with_changed_endorsement_sig.verify();
        assert_verify_err(verify_result, VerifyTokenError::VerificationFailed);

        let (issuer_key, _) = get_issuer_key();
        let changed_issuer_sig =
            PaymentInLieuToken::encode_signature(&issuer_key.sign("abc".as_bytes()));
        let token_with_changed_issuer_sig = PaymentInLieuToken {
            signature: changed_issuer_sig,
            ..token
        };
        let verify_result = token_with_changed_issuer_sig.verify();
        assert_verify_err(verify_result, VerifyTokenError::VerificationFailed);
    }

    fn assert_approval_err(approval_result: ApprovalResult, err: ApprovalError) {
        assert!(approval_result.is_err());
        assert_eq!(approval_result.unwrap_err(), err);
    }

    #[test]
    fn test_approve_payment_in_lieu() {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });

        let approval = approve(ApproveParams {
            token: token.clone(),
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        check_approval(
            &token,
            approval,
            ExpectedPaymentInLieuApproval {
                endorsement_key,
                endorser_base58_public_key: base58_endorsement_key,
            },
        );
    }

    #[test]
    fn test_approve_payment_in_lieu_err_endorsement_expired() {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });

        let approval_result = approve(ApproveParams {
            token: token.clone(),
            now_utc_seconds: endorsement_expiration_time + 5,
        });
        assert_approval_err(approval_result, ApprovalError::EndorsementExpired);

        let approval_result = approve(ApproveParams {
            token,
            now_utc_seconds: endorsement_expiration_time,
        });
        assert_approval_err(approval_result, ApprovalError::EndorsementExpired);
    }

    #[test]
    fn test_approve_payment_in_lieu_err_invalid_sig_encoding() {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });
        let sig_bytes = token.decode_signature().unwrap().to_bytes();

        let utf8_sig = String::from_utf8_lossy(&sig_bytes).into_owned();
        let token_with_utf8_sig = PaymentInLieuToken {
            signature: utf8_sig,
            ..token
        };
        let approval_result = approve(ApproveParams {
            token: token_with_utf8_sig,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::InvalidSignatureEncoding),
        );
    }

    #[test]
    fn test_approve_payment_in_lieu_err_invalid_sig_bytes() {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });
        let sig_bytes = token.decode_signature().unwrap().to_bytes();

        let invalid_sig_bytes = &sig_bytes[..sig_bytes.len() - 5];
        let invalid_sig = base64::engine::general_purpose::STANDARD.encode(invalid_sig_bytes);
        let token_with_invalid_sig_bytes = PaymentInLieuToken {
            signature: invalid_sig,
            ..token.clone()
        };
        let approval_result = approve(ApproveParams {
            token: token_with_invalid_sig_bytes,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::InvalidSignatureBytes),
        );

        let token_with_invalid_sig_bytes = PaymentInLieuToken {
            signature: "".to_owned(),
            ..token
        };
        let approval_result = approve(ApproveParams {
            token: token_with_invalid_sig_bytes,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::InvalidSignatureBytes),
        );
    }

    #[test]
    fn test_approve_payment_in_lieu_err_invalid_issuer_encoding() {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });
        let issuer_bytes = token.decode_issuer().unwrap().to_bytes();

        let base64_issuer = base64::engine::general_purpose::STANDARD.encode(issuer_bytes);
        let token_with_base64_issuer = PaymentInLieuToken {
            issuer: base64_issuer,
            ..token
        };
        let approval_result = approve(ApproveParams {
            token: token_with_base64_issuer,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::InvalidIssuerEncoding),
        );
    }

    #[test]
    fn test_approve_payment_in_lieu_err_invalid_issuer_bytes() {
        let endorsement_expiration_time = 1689028449;
        let token = create_test_token2(CreateTestToken2Params {
            endorsement_expiration_time,
        });
        let issuer_bytes = token.decode_issuer().unwrap().to_bytes();

        let invalid_issuer_bytes = &issuer_bytes[..issuer_bytes.len() - 5];
        let invalid_issuer = bs58::encode(invalid_issuer_bytes).into_string();
        let token_with_invalid_issuer_bytes = PaymentInLieuToken {
            issuer: invalid_issuer,
            ..token.clone()
        };
        let approval_result = approve(ApproveParams {
            token: token_with_invalid_issuer_bytes,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::InvalidIssuerBytes),
        );

        let token_with_invalid_issuer_bytes = PaymentInLieuToken {
            issuer: "".to_owned(),
            ..token
        };
        let approval_result = approve(ApproveParams {
            token: token_with_invalid_issuer_bytes,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::InvalidIssuerBytes),
        );
    }

    #[test]
    fn test_approve_payment_in_lieu_err_verification_failed() {
        let id = "abc";
        let notional = 10000;
        let auction_id = 1;
        let auction_epoch = 2;
        let endorsement_expiration_time = 1689028449;
        let (token, _) = create_test_token(CreateTestTokenParams {
            id,
            notional,
            auction_id,
            auction_epoch,
            endorsement_expiration_time,
        });

        let changed_id = id.to_owned() + "abc";
        let token_with_changed_id = PaymentInLieuToken {
            id: changed_id,
            ..token.clone()
        };
        let approval_result = approve(ApproveParams {
            token: token_with_changed_id,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::VerificationFailed),
        );

        let changed_notional = notional - 1;
        let token_with_changed_notional = PaymentInLieuToken {
            notional: changed_notional,
            ..token.clone()
        };
        let approval_result = approve(ApproveParams {
            token: token_with_changed_notional,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::VerificationFailed),
        );

        let changed_auction_id = auction_id + 1;
        let token_with_changed_auction_id = PaymentInLieuToken {
            auction_id: changed_auction_id,
            ..token.clone()
        };
        let approval_result = approve(ApproveParams {
            token: token_with_changed_auction_id,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::VerificationFailed),
        );

        let changed_auction_epoch = auction_epoch + 1;
        let token_with_changed_auction_epoch = PaymentInLieuToken {
            auction_epoch: changed_auction_epoch,
            ..token.clone()
        };
        let approval_result = approve(ApproveParams {
            token: token_with_changed_auction_epoch,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::VerificationFailed),
        );

        let endorsement_with_changed_sig = Endorsement {
            signature: token.endorsement.signature.to_owned() + "abc",
            ..token.endorsement.clone()
        };
        let token_with_changed_endorsement_sig = PaymentInLieuToken {
            endorsement: endorsement_with_changed_sig,
            ..token.clone()
        };
        let approval_result = approve(ApproveParams {
            token: token_with_changed_endorsement_sig,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::VerificationFailed),
        );

        let (issuer_key, _) = get_issuer_key();
        let changed_issuer_sig =
            PaymentInLieuToken::encode_signature(&issuer_key.sign("abc".as_bytes()));
        let token_with_changed_issuer_sig = PaymentInLieuToken {
            signature: changed_issuer_sig,
            ..token
        };
        let approval_result = approve(ApproveParams {
            token: token_with_changed_issuer_sig,
            now_utc_seconds: endorsement_expiration_time - 30,
        });
        assert_approval_err(
            approval_result,
            ApprovalError::InvalidToken(VerifyTokenError::VerificationFailed),
        );
    }

    fn assert_verify_approval_err(
        verify_result: Result<(), VerifyApprovalError>,
        err: VerifyApprovalError,
    ) {
        assert!(verify_result.is_err());
        assert_eq!(verify_result.unwrap_err(), err);
    }

    #[test]
    fn test_verify_approval() {
        let (token, approval) = create_test_token_and_approval();
        assert!(approval.verify(&token).is_ok());
    }

    #[test]
    fn test_verify_approval_err_invalid_token_signature() {
        let (token, approval) = create_test_token_and_approval();
        let token_sig_bytes = token.decode_signature().unwrap().to_bytes();

        let utf8_token_sig = String::from_utf8_lossy(&token_sig_bytes).into_owned();
        let token_with_utf8_sig = PaymentInLieuToken {
            signature: utf8_token_sig,
            ..token.clone()
        };
        let verify_result = approval.verify(&token_with_utf8_sig);
        assert_verify_approval_err(verify_result, VerifyApprovalError::InvalidTokenSignature);

        let invalid_sig_bytes = &token_sig_bytes[..token_sig_bytes.len() - 5];
        let invalid_token_sig = base64::engine::general_purpose::STANDARD.encode(invalid_sig_bytes);
        let token_with_invalid_sig_bytes = PaymentInLieuToken {
            signature: invalid_token_sig,
            ..token.clone()
        };
        let verify_result = approval.verify(&token_with_invalid_sig_bytes);
        assert_verify_approval_err(verify_result, VerifyApprovalError::InvalidTokenSignature);

        let token_with_invalid_sig_bytes = PaymentInLieuToken {
            signature: "".to_owned(),
            ..token
        };
        let verify_result = approval.verify(&token_with_invalid_sig_bytes);
        assert_verify_approval_err(verify_result, VerifyApprovalError::InvalidTokenSignature);
    }

    #[test]
    fn test_verify_approval_err_invalid_sig_encoding() {
        let (token, approval) = create_test_token_and_approval();
        let sig_bytes = approval.decode_approval().unwrap().to_bytes();

        let utf8_sig = String::from_utf8_lossy(&sig_bytes).into_owned();
        let approval_with_utf8_sig = PaymentInLieuApproval {
            approval: utf8_sig,
            ..approval
        };
        let verify_result = approval_with_utf8_sig.verify(&token);
        assert_verify_approval_err(verify_result, VerifyApprovalError::InvalidApprovalEncoding);
    }

    #[test]
    fn test_verify_approval_err_invalid_sig_bytes() {
        let (token, approval) = create_test_token_and_approval();
        let sig_bytes = approval.decode_approval().unwrap().to_bytes();

        let invalid_sig_bytes = &sig_bytes[..sig_bytes.len() - 5];
        let invalid_sig = base64::engine::general_purpose::STANDARD.encode(invalid_sig_bytes);
        let approval_with_invalid_sig_bytes = PaymentInLieuApproval {
            approval: invalid_sig,
            ..approval.clone()
        };
        let verify_result = approval_with_invalid_sig_bytes.verify(&token);
        assert_verify_approval_err(verify_result, VerifyApprovalError::InvalidApprovalBytes);

        let approval_with_invalid_sig_bytes = PaymentInLieuApproval {
            approval: "".to_owned(),
            ..approval
        };
        let verify_result = approval_with_invalid_sig_bytes.verify(&token);
        assert_verify_approval_err(verify_result, VerifyApprovalError::InvalidApprovalBytes);
    }

    #[test]
    fn test_verify_approval_err_invalid_approver_encoding() {
        let (token, approval) = create_test_token_and_approval();
        let approver_bytes = approval.decode_approver().unwrap().to_bytes();

        let base64_approver = base64::engine::general_purpose::STANDARD.encode(approver_bytes);
        let approval_with_base64_approver = PaymentInLieuApproval {
            approver: base64_approver,
            ..approval
        };
        let verify_result = approval_with_base64_approver.verify(&token);
        assert_verify_approval_err(verify_result, VerifyApprovalError::InvalidApproverEncoding);
    }

    #[test]
    fn test_verify_approval_err_invalid_approver_bytes() {
        let (token, approval) = create_test_token_and_approval();
        let approver_bytes = approval.decode_approver().unwrap().to_bytes();

        let invalid_approver_bytes = &approver_bytes[..approver_bytes.len() - 5];
        let invalid_approver = bs58::encode(invalid_approver_bytes).into_string();
        let approval_with_invalid_approver_bytes = PaymentInLieuApproval {
            approver: invalid_approver,
            ..approval.clone()
        };
        let verify_result = approval_with_invalid_approver_bytes.verify(&token);
        assert_verify_approval_err(verify_result, VerifyApprovalError::InvalidApproverBytes);

        let approval_with_invalid_approver_bytes = PaymentInLieuApproval {
            approver: "".to_owned(),
            ..approval
        };
        let verify_result = approval_with_invalid_approver_bytes.verify(&token);
        assert_verify_approval_err(verify_result, VerifyApprovalError::InvalidApproverBytes);
    }

    #[test]
    fn test_verify_approval_err_verification_failed() {
        let (token, approval) = create_test_token_and_approval();

        let (endorsement_key, _) = get_endorsement_key();
        let changed_approval_signature =
            PaymentInLieuApproval::encode_approval(&endorsement_key.sign("".as_bytes()));
        let approval_with_changed_signature = PaymentInLieuApproval {
            approval: changed_approval_signature,
            ..approval.clone()
        };
        let verify_result = approval_with_changed_signature.verify(&token);
        assert_verify_approval_err(verify_result, VerifyApprovalError::VerificationFailed);

        let (other_token, _) = create_test_token(CreateTestTokenParams {
            id: &token.id,
            notional: token.notional + 1,
            auction_id: token.auction_id,
            auction_epoch: token.auction_epoch,
            endorsement_expiration_time: 1689028449,
        });
        let verify_result = approval.verify(&other_token);
        assert_verify_approval_err(verify_result, VerifyApprovalError::VerificationFailed);
    }
}
