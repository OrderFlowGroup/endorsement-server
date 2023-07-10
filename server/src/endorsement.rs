use base64::Engine as _;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endorsement {
    pub endorser: String,
    pub signature: String,
    pub id: String,
    #[serde(rename = "expirationTimeUTC")]
    pub expiration_time_utc: u64,
    pub data: String,
}

impl Endorsement {
    /// Create an endorsement signed by the `endorsement_key`.
    /// `base58_endorsement_key` must be specified as the Base58-encoded public
    /// key of the endorsement key.
    pub fn new(
        params: &EndorsementParams,
        endorsement_key: &ed25519_dalek::Keypair,
        base58_endorsement_key: &str,
        expiration_time_utc_seconds: u64,
        id: u64,
    ) -> NewEndorsementResult {
        let platform_fee_bps = params.platform_fee_bps.unwrap_or_default();
        let platform_fee_receiver = params.platform_fee_receiver.unwrap_or_default();
        let platform_fee_data: String;
        if !platform_fee_bps.is_empty() && !platform_fee_receiver.is_empty() {
            let bps = Self::parse_platform_fee_bps(platform_fee_bps)
                .map_err(|_| EndorsementError::InvalidPlatformFeeBps)?;
            if bps > 5000 {
                return Err(EndorsementError::PlatformFeeBpsTooHigh);
            }
            platform_fee_data =
                Self::make_platform_fee_data(platform_fee_bps, platform_fee_receiver);
        } else if !platform_fee_bps.is_empty() {
            return Err(EndorsementError::PlatformFeeReceiverNotSpecified);
        } else if !platform_fee_receiver.is_empty() {
            return Err(EndorsementError::PlatformFeeBpsNotSpecified);
        } else {
            platform_fee_data = String::from("");
        }

        let send_token = params.send_token.unwrap_or_default();
        let send_qty = params.send_qty.unwrap_or_default();
        let max_send_qty = params.max_send_qty.unwrap_or_default();
        if !send_qty.is_empty() && !max_send_qty.is_empty() {
            return Err(EndorsementError::SendQtyAndMaxSendQtySpecified);
        } else if !send_qty.is_empty() {
            if send_token.is_empty() {
                return Err(EndorsementError::SendQtyRequiresSendToken);
            }
            let qty =
                Self::parse_send_qty(send_qty).map_err(|_| EndorsementError::InvalidSendQty)?;
            if qty == 0 {
                return Err(EndorsementError::InvalidSendQty);
            }
        } else if !max_send_qty.is_empty() {
            if send_token.is_empty() {
                return Err(EndorsementError::MaxSendQtyRequiresSendToken);
            }
            let qty = Self::parse_send_qty(max_send_qty)
                .map_err(|_| EndorsementError::InvalidMaxSendQty)?;
            if qty == 0 {
                return Err(EndorsementError::InvalidMaxSendQty);
            }
        }

        let retail_trader = params.retail_trader.unwrap_or_default();
        let receive_token = params.receive_token.unwrap_or_default();

        let data = Self::make_endorsement_data(MakeEndorsementDataParams {
            retail_trader,
            platform_fee_data: &platform_fee_data,
            send_token,
            receive_token,
            send_qty,
            max_send_qty,
        });

        let encoded_id = Self::encode_id(id);
        let msg = Self::make_endorsement_msg(&encoded_id, expiration_time_utc_seconds, &data);

        let sig = endorsement_key.sign(&msg);
        let encoded_sig = Self::encode_signature(&sig);

        Ok(Self {
            endorser: base58_endorsement_key.to_owned(),
            signature: encoded_sig,
            id: encoded_id,
            expiration_time_utc: expiration_time_utc_seconds,
            data,
        })
    }

    #[allow(dead_code)]
    /// Verify the endorser's signature of the endorsement.
    pub fn verify(&self) -> Result<(), VerifyEndorsementError> {
        let msg = Self::make_endorsement_msg(&self.id, self.expiration_time_utc, &self.data);
        let sig = self.decode_signature()?;
        let endorser_public_key = self.decode_endorser()?;
        endorser_public_key
            .verify_strict(&msg, &sig)
            .map_err(|_| VerifyEndorsementError::VerificationFailed)
    }

    fn make_endorsement_msg(base64_id: &str, expiration_time_utc: u64, data: &str) -> Vec<u8> {
        format!("{base64_id},{expiration_time_utc},{data}").into()
    }

    fn encode_id(id: u64) -> String {
        base64::engine::general_purpose::STANDARD.encode(id.to_be_bytes())
    }

    fn make_endorsement_data(params: MakeEndorsementDataParams) -> String {
        format!(
            "1|{}|{}|{}|{}|{}|{}",
            params.retail_trader,
            params.platform_fee_data,
            params.send_token,
            params.receive_token,
            params.send_qty,
            params.max_send_qty,
        )
    }

    fn make_platform_fee_data(non_empty_bps: &str, non_empty_receiver: &str) -> String {
        format!("{non_empty_bps},{non_empty_receiver}")
    }

    fn parse_platform_fee_bps(raw: &str) -> Result<u16, std::num::ParseIntError> {
        raw.parse::<u16>()
    }

    fn parse_send_qty(raw: &str) -> Result<u64, std::num::ParseIntError> {
        raw.parse::<u64>()
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
    /// Returns the endorser's public key as a Base58-encoded string.
    pub fn encode_endorser(endorser: &ed25519_dalek::PublicKey) -> String {
        bs58::encode(endorser.as_bytes()).into_string()
    }

    fn decode_endorser(&self) -> Result<ed25519_dalek::PublicKey, DecodeEndorserError> {
        let endorser_bytes = bs58::decode(&self.endorser)
            .into_vec()
            .map_err(|_| DecodeEndorserError::InvalidEncoding)?;
        ed25519_dalek::PublicKey::from_bytes(&endorser_bytes)
            .map_err(|_| DecodeEndorserError::InvalidBytes)
    }
}

#[derive(Debug)]
pub struct EndorsementParams<'a> {
    pub retail_trader: Option<&'a str>,
    pub platform_fee_bps: Option<&'a str>,
    pub platform_fee_receiver: Option<&'a str>,
    pub send_token: Option<&'a str>,
    pub receive_token: Option<&'a str>,
    pub send_qty: Option<&'a str>,
    pub max_send_qty: Option<&'a str>,
}

#[derive(Debug, PartialEq)]
pub enum EndorsementError {
    InvalidPlatformFeeBps,
    PlatformFeeBpsTooHigh,
    PlatformFeeBpsNotSpecified,
    PlatformFeeReceiverNotSpecified,
    SendQtyAndMaxSendQtySpecified,
    SendQtyRequiresSendToken,
    MaxSendQtyRequiresSendToken,
    InvalidSendQty,
    InvalidMaxSendQty,
}

#[derive(Debug, PartialEq)]
pub enum VerifyEndorsementError {
    InvalidSignatureEncoding,
    InvalidSignatureBytes,
    InvalidEndorserEncoding,
    InvalidEndorserBytes,
    VerificationFailed,
}

#[derive(Debug, PartialEq)]
pub enum DecodeSignatureError {
    InvalidEncoding,
    InvalidBytes,
}

#[derive(Debug, PartialEq)]
pub enum DecodeEndorserError {
    InvalidEncoding,
    InvalidBytes,
}

impl From<DecodeSignatureError> for VerifyEndorsementError {
    fn from(inner: DecodeSignatureError) -> Self {
        match inner {
            DecodeSignatureError::InvalidEncoding => Self::InvalidSignatureEncoding,
            DecodeSignatureError::InvalidBytes => Self::InvalidSignatureBytes,
        }
    }
}

impl From<DecodeEndorserError> for VerifyEndorsementError {
    fn from(inner: DecodeEndorserError) -> Self {
        match inner {
            DecodeEndorserError::InvalidEncoding => Self::InvalidEndorserEncoding,
            DecodeEndorserError::InvalidBytes => Self::InvalidEndorserBytes,
        }
    }
}

struct MakeEndorsementDataParams<'a> {
    pub retail_trader: &'a str,
    pub platform_fee_data: &'a str,
    pub send_token: &'a str,
    pub receive_token: &'a str,
    pub send_qty: &'a str,
    pub max_send_qty: &'a str,
}

type NewEndorsementResult = Result<Endorsement, EndorsementError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn get_endorsement_key() -> (ed25519_dalek::Keypair, String) {
        let secret_key_bytes: &[u8] = &[
            163, 149, 135, 21, 131, 252, 66, 166, 218, 129, 77, 126, 252, 115, 128, 179, 140, 205,
            50, 134, 251, 100, 23, 49, 139, 32, 136, 154, 33, 221, 59, 160, 93, 175, 53, 246, 159,
            212, 84, 105, 99, 223, 22, 174, 67, 128, 24, 158, 93, 24, 214, 22, 228, 40, 163, 142,
            206, 34, 10, 11, 22, 111, 152, 168,
        ];
        let endorsement_key = ed25519_dalek::Keypair::from_bytes(secret_key_bytes).unwrap();
        let base58_endorsement_key = Endorsement::encode_endorser(&endorsement_key.public);
        (endorsement_key, base58_endorsement_key)
    }

    static NO_ENDORSEMENT_PARAMS: EndorsementParams = EndorsementParams {
        retail_trader: None,
        platform_fee_bps: None,
        platform_fee_receiver: None,
        send_token: None,
        receive_token: None,
        send_qty: None,
        max_send_qty: None,
    };

    static NO_ENDORSEMENT_PARAMS_EMPTY_STRINGS: EndorsementParams = EndorsementParams {
        retail_trader: Some(""),
        platform_fee_bps: Some(""),
        platform_fee_receiver: Some(""),
        send_token: Some(""),
        receive_token: Some(""),
        send_qty: Some(""),
        max_send_qty: Some(""),
    };

    struct CreateTestEndorsementParams<'a> {
        endorsement_params: &'a EndorsementParams<'a>,
        id: u64,
        expiration_time_utc: u64,
    }

    fn create_test_endorsement(params: CreateTestEndorsementParams) -> NewEndorsementResult {
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        Endorsement::new(
            params.endorsement_params,
            &endorsement_key,
            &base58_endorsement_key,
            params.expiration_time_utc,
            params.id,
        )
    }

    fn create_test_endorsement2(params: &EndorsementParams) -> NewEndorsementResult {
        create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: params,
            id: 0,
            expiration_time_utc: 0,
        })
    }

    struct ExpectedEndorsement<'a> {
        pub endorsement_key: ed25519_dalek::Keypair,
        pub endorser_base58_public_key: String,
        pub id: u64,
        pub expiration_time_utc: u64,
        pub data: &'a str,
    }

    fn check_endorsement(actual: NewEndorsementResult, expected: ExpectedEndorsement) {
        assert!(actual.is_ok());
        let actual = actual.unwrap();

        let expected_encoded_id = Endorsement::encode_id(expected.id);
        let msg = Endorsement::make_endorsement_msg(
            &expected_encoded_id,
            expected.expiration_time_utc,
            expected.data,
        );
        let expected_signature =
            Endorsement::encode_signature(&expected.endorsement_key.sign(&msg));

        assert_eq!(actual.endorser, expected.endorser_base58_public_key);
        assert_eq!(actual.signature, expected_signature);
        assert_eq!(actual.id, expected_encoded_id);
        assert_eq!(actual.expiration_time_utc, expected.expiration_time_utc);
        assert_eq!(actual.data, expected.data);

        assert!(actual.verify().is_ok());
    }

    fn assert_endorsement_err(endorsement: NewEndorsementResult, err: EndorsementError) {
        assert!(endorsement.is_err());
        assert_eq!(endorsement.unwrap_err(), err);
    }

    #[test]
    fn test_create_endorsement_no_params() {
        let id: u64 = 802801813;
        let expiration_time_utc: u64 = 1689028449;

        let endorsement = create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: &NO_ENDORSEMENT_PARAMS,
            id,
            expiration_time_utc,
        });
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        check_endorsement(
            endorsement,
            ExpectedEndorsement {
                endorsement_key,
                endorser_base58_public_key: base58_endorsement_key,
                id,
                expiration_time_utc,
                data: "1||||||",
            },
        );

        let endorsement = create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: &NO_ENDORSEMENT_PARAMS_EMPTY_STRINGS,
            id,
            expiration_time_utc,
        });
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        check_endorsement(
            endorsement,
            ExpectedEndorsement {
                endorsement_key,
                endorser_base58_public_key: base58_endorsement_key,
                id,
                expiration_time_utc,
                data: "1||||||",
            },
        );
    }

    #[test]
    fn test_create_endorsement_with_params() {
        let id: u64 = 802801813;
        let expiration_time_utc: u64 = 1689028449;

        let endorsement = create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: &EndorsementParams {
                retail_trader: Some("rt"),
                platform_fee_bps: None,
                platform_fee_receiver: None,
                send_token: None,
                receive_token: None,
                send_qty: None,
                max_send_qty: None,
            },
            id,
            expiration_time_utc,
        });
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        check_endorsement(
            endorsement,
            ExpectedEndorsement {
                endorsement_key,
                endorser_base58_public_key: base58_endorsement_key,
                id,
                expiration_time_utc,
                data: "1|rt|||||",
            },
        );

        let endorsement = create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: &EndorsementParams {
                retail_trader: Some("rt"),
                platform_fee_bps: Some("50"),
                platform_fee_receiver: Some("pfr"),
                send_token: None,
                receive_token: None,
                send_qty: None,
                max_send_qty: None,
            },
            id,
            expiration_time_utc,
        });
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        check_endorsement(
            endorsement,
            ExpectedEndorsement {
                endorsement_key,
                endorser_base58_public_key: base58_endorsement_key,
                id,
                expiration_time_utc,
                data: "1|rt|50,pfr||||",
            },
        );

        let endorsement = create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: &EndorsementParams {
                retail_trader: Some("rt"),
                platform_fee_bps: Some("50"),
                platform_fee_receiver: Some("pfr"),
                send_token: Some("sendtoken"),
                receive_token: Some("recvtoken"),
                send_qty: Some("1000000"),
                max_send_qty: None,
            },
            id,
            expiration_time_utc,
        });
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        check_endorsement(
            endorsement,
            ExpectedEndorsement {
                endorsement_key,
                endorser_base58_public_key: base58_endorsement_key,
                id,
                expiration_time_utc,
                data: "1|rt|50,pfr|sendtoken|recvtoken|1000000|",
            },
        );

        let endorsement = create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: &EndorsementParams {
                retail_trader: Some("rt"),
                platform_fee_bps: Some("50"),
                platform_fee_receiver: Some("pfr"),
                send_token: Some("sendtoken"),
                receive_token: Some("recvtoken"),
                send_qty: Some("1000000"),
                max_send_qty: None,
            },
            id,
            expiration_time_utc,
        });
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        check_endorsement(
            endorsement,
            ExpectedEndorsement {
                endorsement_key,
                endorser_base58_public_key: base58_endorsement_key,
                id,
                expiration_time_utc,
                data: "1|rt|50,pfr|sendtoken|recvtoken|1000000|",
            },
        );

        let endorsement = create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: &EndorsementParams {
                retail_trader: Some("rt"),
                platform_fee_bps: Some("50"),
                platform_fee_receiver: Some("pfr"),
                send_token: Some("sendtoken"),
                receive_token: Some("recvtoken"),
                send_qty: None,
                max_send_qty: Some("1000000"),
            },
            id,
            expiration_time_utc,
        });
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        check_endorsement(
            endorsement,
            ExpectedEndorsement {
                endorsement_key,
                endorser_base58_public_key: base58_endorsement_key,
                id,
                expiration_time_utc,
                data: "1|rt|50,pfr|sendtoken|recvtoken||1000000",
            },
        );

        let endorsement = create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: &EndorsementParams {
                retail_trader: None,
                platform_fee_bps: None,
                platform_fee_receiver: None,
                send_token: Some("sendtoken"),
                receive_token: None,
                send_qty: Some("1000000"),
                max_send_qty: None,
            },
            id,
            expiration_time_utc,
        });
        let (endorsement_key, base58_endorsement_key) = get_endorsement_key();
        check_endorsement(
            endorsement,
            ExpectedEndorsement {
                endorsement_key,
                endorser_base58_public_key: base58_endorsement_key,
                id,
                expiration_time_utc,
                data: "1|||sendtoken||1000000|",
            },
        );
    }

    #[test]
    fn test_create_endorsement_err_platform_fee_bps_not_uint() {
        let endorsement = create_test_endorsement2(&EndorsementParams {
            platform_fee_bps: Some("-5"),
            platform_fee_receiver: Some("abc"),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::InvalidPlatformFeeBps);

        let endorsement = create_test_endorsement2(&EndorsementParams {
            platform_fee_bps: Some("0.5"),
            platform_fee_receiver: Some("abc"),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::InvalidPlatformFeeBps);
    }

    #[test]
    fn test_create_endorsement_err_platform_fee_bps_too_high() {
        let endorsement = create_test_endorsement2(&EndorsementParams {
            platform_fee_bps: Some("5001"),
            platform_fee_receiver: Some("abc"),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::PlatformFeeBpsTooHigh);
    }

    #[test]
    fn test_create_endorsement_err_platform_fee_unspecified_receiver() {
        let endorsement = create_test_endorsement2(&EndorsementParams {
            platform_fee_bps: Some("85"),
            platform_fee_receiver: None,
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(
            endorsement,
            EndorsementError::PlatformFeeReceiverNotSpecified,
        );

        let endorsement = create_test_endorsement2(&EndorsementParams {
            platform_fee_bps: Some("85"),
            platform_fee_receiver: Some(""),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(
            endorsement,
            EndorsementError::PlatformFeeReceiverNotSpecified,
        );
    }

    #[test]
    fn test_create_endorsement_err_platform_fee_unspecified_bps() {
        let endorsement = create_test_endorsement2(&EndorsementParams {
            platform_fee_receiver: Some("abc"),
            platform_fee_bps: None,
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::PlatformFeeBpsNotSpecified);

        let endorsement = create_test_endorsement2(&EndorsementParams {
            platform_fee_receiver: Some("abc"),
            platform_fee_bps: Some(""),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::PlatformFeeBpsNotSpecified);
    }

    #[test]
    fn test_create_endorsement_err_both_send_qty_specified() {
        let endorsement = create_test_endorsement2(&EndorsementParams {
            send_qty: Some("1000000"),
            max_send_qty: Some("1000000"),
            send_token: Some("abc"),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::SendQtyAndMaxSendQtySpecified);

        let endorsement = create_test_endorsement2(&EndorsementParams {
            send_qty: Some("1000000"),
            max_send_qty: Some("foo"),
            send_token: Some("abc"),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::SendQtyAndMaxSendQtySpecified);
    }

    #[test]
    fn test_create_endorsement_err_send_qty_specified_without_send_token() {
        let endorsement = create_test_endorsement2(&EndorsementParams {
            send_qty: Some("1000000"),
            send_token: None,
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::SendQtyRequiresSendToken);

        let endorsement = create_test_endorsement2(&EndorsementParams {
            send_qty: Some("1000000"),
            send_token: Some(""),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::SendQtyRequiresSendToken);
    }

    #[test]
    fn test_create_endorsement_err_max_send_qty_specified_without_send_token() {
        let endorsement = create_test_endorsement2(&EndorsementParams {
            max_send_qty: Some("1000000"),
            send_token: None,
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::MaxSendQtyRequiresSendToken);

        let endorsement = create_test_endorsement2(&EndorsementParams {
            max_send_qty: Some("1000000"),
            send_token: Some(""),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::MaxSendQtyRequiresSendToken);
    }

    #[test]
    fn test_create_endorsement_err_send_qty_not_uint() {
        let endorsement = create_test_endorsement2(&EndorsementParams {
            send_qty: Some("-5"),
            send_token: Some("abc"),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::InvalidSendQty);

        let endorsement = create_test_endorsement2(&EndorsementParams {
            send_qty: Some("0.5"),
            send_token: Some("abc"),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::InvalidSendQty);
    }

    #[test]
    fn test_create_endorsement_err_max_send_qty_not_uint() {
        let endorsement = create_test_endorsement2(&EndorsementParams {
            max_send_qty: Some("-5"),
            send_token: Some("abc"),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::InvalidMaxSendQty);

        let endorsement = create_test_endorsement2(&EndorsementParams {
            max_send_qty: Some("0.5"),
            send_token: Some("abc"),
            ..NO_ENDORSEMENT_PARAMS
        });
        assert_endorsement_err(endorsement, EndorsementError::InvalidMaxSendQty);
    }

    fn assert_verify_err(
        verify_result: Result<(), VerifyEndorsementError>,
        err: VerifyEndorsementError,
    ) {
        assert!(verify_result.is_err());
        assert_eq!(verify_result.unwrap_err(), err);
    }

    #[test]
    fn test_verify_endorsement() {
        let endorsement = create_test_endorsement2(&NO_ENDORSEMENT_PARAMS).unwrap();
        assert!(endorsement.verify().is_ok());
    }

    #[test]
    fn test_verify_endorsement_err_invalid_sig_encoding() {
        let endorsement = create_test_endorsement2(&NO_ENDORSEMENT_PARAMS).unwrap();
        let sig_bytes = endorsement.decode_signature().unwrap().to_bytes();

        let utf8_sig = String::from_utf8_lossy(&sig_bytes).into_owned();
        let endorsement_with_utf8_sig = Endorsement {
            signature: utf8_sig,
            ..endorsement
        };
        let verify_result = endorsement_with_utf8_sig.verify();
        assert_verify_err(
            verify_result,
            VerifyEndorsementError::InvalidSignatureEncoding,
        );
    }

    #[test]
    fn test_verify_endorsement_err_invalid_sig_bytes() {
        let endorsement = create_test_endorsement2(&NO_ENDORSEMENT_PARAMS).unwrap();
        let sig_bytes = endorsement.decode_signature().unwrap().to_bytes();

        let invalid_sig_bytes = &sig_bytes[..sig_bytes.len() - 5];
        let invalid_sig = base64::engine::general_purpose::STANDARD.encode(invalid_sig_bytes);
        let endorsement_with_invalid_sig_bytes = Endorsement {
            signature: invalid_sig,
            ..endorsement.clone()
        };
        let verify_result = endorsement_with_invalid_sig_bytes.verify();
        assert_verify_err(verify_result, VerifyEndorsementError::InvalidSignatureBytes);

        let endorsement_with_invalid_sig_bytes = Endorsement {
            signature: "".to_owned(),
            ..endorsement
        };
        let verify_result = endorsement_with_invalid_sig_bytes.verify();
        assert_verify_err(verify_result, VerifyEndorsementError::InvalidSignatureBytes);
    }

    #[test]
    fn test_verify_endorsement_err_invalid_endorser_encoding() {
        let endorsement = create_test_endorsement2(&NO_ENDORSEMENT_PARAMS).unwrap();
        let endorser_bytes = endorsement.decode_endorser().unwrap().to_bytes();

        let base64_endorser = base64::engine::general_purpose::STANDARD.encode(endorser_bytes);
        let endorsement_with_base64_endorser = Endorsement {
            endorser: base64_endorser,
            ..endorsement
        };
        let verify_result = endorsement_with_base64_endorser.verify();
        assert_verify_err(
            verify_result,
            VerifyEndorsementError::InvalidEndorserEncoding,
        );
    }

    #[test]
    fn test_verify_endorsement_err_invalid_endorser_bytes() {
        let endorsement = create_test_endorsement2(&NO_ENDORSEMENT_PARAMS).unwrap();
        let endorser_bytes = endorsement.decode_endorser().unwrap().to_bytes();

        let invalid_endorser_bytes = &endorser_bytes[..endorser_bytes.len() - 5];
        let invalid_endorser = bs58::encode(invalid_endorser_bytes).into_string();
        let endorsement_with_invalid_endorser_bytes = Endorsement {
            endorser: invalid_endorser,
            ..endorsement.clone()
        };
        let verify_result = endorsement_with_invalid_endorser_bytes.verify();
        assert_verify_err(verify_result, VerifyEndorsementError::InvalidEndorserBytes);

        let endorsement_with_invalid_endorser_bytes = Endorsement {
            endorser: "".to_owned(),
            ..endorsement
        };
        let verify_result = endorsement_with_invalid_endorser_bytes.verify();
        assert_verify_err(verify_result, VerifyEndorsementError::InvalidEndorserBytes);
    }

    #[test]
    fn test_verify_endorsement_err_verification_failed() {
        let id = 0;
        let expiration_time_utc = 0;
        let endorsement = create_test_endorsement(CreateTestEndorsementParams {
            endorsement_params: &NO_ENDORSEMENT_PARAMS,
            id,
            expiration_time_utc,
        })
        .unwrap();

        let changed_base64_id = Endorsement::encode_id(id + 1);
        let endorsement_with_changed_id = Endorsement {
            id: changed_base64_id,
            ..endorsement.clone()
        };
        let verify_result = endorsement_with_changed_id.verify();
        assert_verify_err(verify_result, VerifyEndorsementError::VerificationFailed);

        let changed_expiration_time_utc = expiration_time_utc + 1;
        let endorsement_with_changed_expiration_time_utc = Endorsement {
            expiration_time_utc: changed_expiration_time_utc,
            ..endorsement.clone()
        };
        let verify_result = endorsement_with_changed_expiration_time_utc.verify();
        assert_verify_err(verify_result, VerifyEndorsementError::VerificationFailed);

        let changed_data = endorsement.data.to_owned() + "abc";
        let endorsement_with_changed_data = Endorsement {
            data: changed_data,
            ..endorsement.clone()
        };
        let verify_result = endorsement_with_changed_data.verify();
        assert_verify_err(verify_result, VerifyEndorsementError::VerificationFailed);

        let (endorsement_key, _) = get_endorsement_key();
        let changed_sig = Endorsement::encode_signature(&endorsement_key.sign("abc".as_bytes()));
        let endorsement_with_changed_sig = Endorsement {
            signature: changed_sig,
            ..endorsement
        };
        let verify_result = endorsement_with_changed_sig.verify();
        assert_verify_err(verify_result, VerifyEndorsementError::VerificationFailed);
    }
}
