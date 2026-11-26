use jsonwebtoken::jwk::{Jwk, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

use crate::error::{ClientError, Result};
use crate::types::ServiceAccessTokenClaims;

pub fn decode_header_kid(token: &str) -> Result<Option<String>> {
    let header = decode_header(token).map_err(|error| ClientError::Token(error.to_string()))?;
    Ok(header.kid)
}

pub fn validate_with_jwk(
    token: &str,
    jwk: &Jwk,
    expected_audience: Option<&str>,
    expected_issuer: Option<&str>,
) -> Result<ServiceAccessTokenClaims> {
    let decoding_key =
        DecodingKey::from_jwk(jwk).map_err(|error| ClientError::Token(error.to_string()))?;

    let mut validation = Validation::new(algorithm_for_jwk(jwk, token)?);
    validation.validate_exp = true;
    validation.validate_nbf = true;

    if let Some(audience) = expected_audience {
        validation.set_audience(&[audience]);
    } else {
        validation.validate_aud = false;
    }

    if let Some(issuer) = expected_issuer {
        validation.set_issuer(&[issuer]);
    }

    let token_data = decode::<ServiceAccessTokenClaims>(token, &decoding_key, &validation)
        .map_err(|error| ClientError::Token(error.to_string()))?;

    let claims = token_data.claims;
    if claims.iss != expected_issuer.unwrap_or("panchayat-core") {
        return Err(ClientError::Token("invalid issuer".to_owned()));
    }

    Ok(claims)
}

fn algorithm_for_jwk(jwk: &Jwk, token: &str) -> Result<Algorithm> {
    match jwk.common.key_algorithm {
        Some(KeyAlgorithm::RS256) => Ok(Algorithm::RS256),
        Some(KeyAlgorithm::ES256) => Ok(Algorithm::ES256),
        Some(_) => Err(ClientError::Token(
            "unsupported signing algorithm".to_owned(),
        )),
        None => {
            let header =
                decode_header(token).map_err(|error| ClientError::Token(error.to_string()))?;
            match header.alg {
                Algorithm::RS256 | Algorithm::ES256 => Ok(header.alg),
                _ => Err(ClientError::Token(
                    "unsupported signing algorithm".to_owned(),
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
        EllipticCurveKeyType, PublicKeyUse,
    };
    use jsonwebtoken::{EncodingKey, Header, encode};
    use uuid::Uuid;

    // Test-only P-256 key pair. Never use this outside the test suite.
    const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgolFFJCL7dRDCLBJI\n\
XmI5ssMlxY53Sb8aUMnGAqtuXkihRANCAAS0RzJOhkyhSlJZgvr7pqnntviQhMWF\n\
1RRorlxrnb28tB8od30RqiUPYMM57uvvI9afsdRLjGpPlPa+THqXKCvZ\n\
-----END PRIVATE KEY-----\n";
    const TEST_JWK_X: &str = "tEcyToZMoUpSWYL6-6ap57b4kITFhdUUaK5ca529vLQ";
    const TEST_JWK_Y: &str = "Hyh3fRGqJQ9gwznu6-8j1p-x1EuMak-U9r5MepcoK9k";

    fn test_jwk() -> Jwk {
        Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_operations: None,
                key_algorithm: Some(KeyAlgorithm::ES256),
                key_id: Some("test-kid".to_owned()),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x: TEST_JWK_X.to_owned(),
                y: TEST_JWK_Y.to_owned(),
            }),
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn test_claims(iss: &str, aud: &str) -> ServiceAccessTokenClaims {
        ServiceAccessTokenClaims {
            iss: iss.to_owned(),
            sub: Uuid::now_v7(),
            aud: aud.to_owned(),
            iat: now(),
            exp: now() + 300,
            nbf: now(),
            jti: Uuid::now_v7(),
            authorization_version: 3,
            operations: vec!["read".to_owned()],
            cnf: None,
        }
    }

    fn signed_token(claims: &ServiceAccessTokenClaims) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("test-kid".to_owned());
        header.typ = Some("JWT".to_owned());
        let encoding_key = EncodingKey::from_ec_pem(TEST_PRIVATE_KEY_PEM.as_bytes()).unwrap();
        encode(&header, claims, &encoding_key).unwrap()
    }

    #[test]
    fn validates_es256_token_signed_with_matching_jwk() {
        let claims = test_claims("panchayat-core", "receiving-service");
        let token = signed_token(&claims);

        let validated = validate_with_jwk(
            &token,
            &test_jwk(),
            Some("receiving-service"),
            Some("panchayat-core"),
        )
        .unwrap();

        assert_eq!(validated.aud, "receiving-service");
        assert_eq!(validated.authorization_version, 3);
    }

    #[test]
    fn rejects_wrong_audience() {
        let token = signed_token(&test_claims("panchayat-core", "receiving-service"));

        let result = validate_with_jwk(
            &token,
            &test_jwk(),
            Some("other-service"),
            Some("panchayat-core"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_issuer() {
        let token = signed_token(&test_claims("not-core", "receiving-service"));

        let result = validate_with_jwk(&token, &test_jwk(), None, Some("panchayat-core"));
        assert!(result.is_err());
    }
}
