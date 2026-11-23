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
