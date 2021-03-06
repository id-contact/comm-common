use crate::types::AuthSelectParams;
#[cfg(feature = "auth_during_comm")]
use id_contact_proto::StartRequestAuthOnly;
use josekit::{
    jws::{JwsHeader, JwsSigner},
    jwt::JwtPayload,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Invalid Structure for key {0}")]
    InvalidStructure(&'static str),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("24 Sessions JWT error: {0}")]
    Jwt(#[from] josekit::JoseError),
    #[error("ID Contact JWE error: {0}")]
    Jwe(#[from] id_contact_jwt::Error),
}

#[cfg(feature = "auth_during_comm")]
pub fn sign_start_auth_request(
    request: StartRequestAuthOnly,
    kid: &str,
    signer: &dyn JwsSigner,
) -> Result<String, JwtError> {
    let mut sig_header = JwsHeader::new();
    sig_header.set_token_type("JWT");
    sig_header.set_key_id(kid);
    let mut sig_payload = JwtPayload::new();
    sig_payload.set_claim("request", Some(serde_json::to_value(request)?))?;
    sig_payload.set_issued_at(&std::time::SystemTime::now());
    sig_payload
        .set_expires_at(&(std::time::SystemTime::now() + std::time::Duration::from_secs(5 * 60)));
    Ok(josekit::jwt::encode_with_signer(
        &sig_payload,
        &sig_header,
        signer,
    )?)
}

/// Serialize and sign a set of AuthSelectParams for use in the auth-select menu
pub fn sign_auth_select_params(
    params: AuthSelectParams,
    signer: &dyn JwsSigner,
) -> Result<String, JwtError> {
    let mut sig_header = JwsHeader::new();
    sig_header.set_token_type("JWT");
    let mut sig_payload = JwtPayload::new();
    sig_payload.set_subject("id-contact-widget-params");

    sig_payload.set_claim("purpose", Some(serde_json::to_value(&params.purpose)?))?;
    sig_payload.set_claim("start_url", Some(serde_json::to_value(&params.start_url)?))?;
    sig_payload.set_claim(
        "display_name",
        Some(serde_json::to_value(&params.display_name)?),
    )?;

    sig_payload.set_issued_at(&std::time::SystemTime::now());
    sig_payload
        .set_expires_at(&(std::time::SystemTime::now() + std::time::Duration::from_secs(5 * 60)));

    let jws = josekit::jwt::encode_with_signer(&sig_payload, &sig_header, signer)?;

    Ok(jws)
}
