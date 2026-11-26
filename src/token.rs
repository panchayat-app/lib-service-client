use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

use crate::error::{ClientError, Result};
use crate::types::ServiceAccessTokenClaims;

pub fn decode_header_kid(token: &str) -> Result<Option<String>> {
    let header = decode_header(token).map_err(|error| ClientError::Token(error.to_string()))?;
    Ok(header.kid)
}

pub fn validate_with_jwk(
    token: &str,
    jwk: &jsonwebtoken::jwk::Jwk,
    expected_audience: Option<&str>,
    expected_issuer: Option<&str>,
) -> Result<ServiceAccessTokenClaims> {
    let decoding_key =
        DecodingKey::from_jwk(jwk).map_err(|error| ClientError::Token(error.to_string()))?;

    let mut validation = Validation::new(Algorithm::RS256);
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rsa::RsaPrivateKey;
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::traits::PublicKeyParts;
    use uuid::Uuid;

    fn generate_key() -> (String, jsonwebtoken::jwk::Jwk) {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public = private.to_public_key();
        let private_pem = private.to_pkcs1_pem(LineEnding::LF).unwrap().to_string();

        let jwk = jsonwebtoken::jwk::Jwk {
            common: jsonwebtoken::jwk::CommonParameters {
                public_key_use: Some(jsonwebtoken::jwk::PublicKeyUse::Signature),
                key_operations: None,
                key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::RS256),
                key_id: Some("test-kid".to_owned()),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: jsonwebtoken::jwk::AlgorithmParameters::RSA(
                jsonwebtoken::jwk::RSAKeyParameters {
                    key_type: jsonwebtoken::jwk::RSAKeyType::RSA,
                    n: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                    e: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
                },
            ),
        };

        (private_pem, jwk)
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    #[test]
    fn validates_token_signed_with_matching_jwk() {
        let (private_pem, jwk) = generate_key();
        let claims = ServiceAccessTokenClaims {
            iss: "panchayat-core".to_owned(),
            sub: Uuid::now_v7(),
            aud: "receiving-service".to_owned(),
            iat: now(),
            exp: now() + 300,
            nbf: now(),
            jti: Uuid::now_v7(),
            authorization_version: 3,
            operations: vec!["read".to_owned()],
            cnf: None,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_owned());
        header.typ = Some("JWT".to_owned());
        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap();
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let validated = validate_with_jwk(
            &token,
            &jwk,
            Some("receiving-service"),
            Some("panchayat-core"),
        )
        .unwrap();

        assert_eq!(validated.aud, "receiving-service");
        assert_eq!(validated.authorization_version, 3);
    }

    #[test]
    fn rejects_wrong_audience() {
        let (private_pem, jwk) = generate_key();
        let claims = ServiceAccessTokenClaims {
            iss: "panchayat-core".to_owned(),
            sub: Uuid::now_v7(),
            aud: "receiving-service".to_owned(),
            iat: now(),
            exp: now() + 300,
            nbf: now(),
            jti: Uuid::now_v7(),
            authorization_version: 1,
            operations: vec![],
            cnf: None,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_owned());
        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap();
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validate_with_jwk(&token, &jwk, Some("other-service"), Some("panchayat-core"));
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_issuer() {
        let (private_pem, jwk) = generate_key();
        let claims = ServiceAccessTokenClaims {
            iss: "not-core".to_owned(),
            sub: Uuid::now_v7(),
            aud: "receiving-service".to_owned(),
            iat: now(),
            exp: now() + 300,
            nbf: now(),
            jti: Uuid::now_v7(),
            authorization_version: 1,
            operations: vec![],
            cnf: None,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_owned());
        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap();
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = validate_with_jwk(&token, &jwk, None, Some("panchayat-core"));
        assert!(result.is_err());
    }
}
