use crate::jwt::JwtError;
use rocket::{
    http::{ContentType, Status},
    Response,
};
use rocket_sync_db_pools::postgres;
use serde_json::json;
use tera;
use thiserror::Error;

#[derive(Debug, Error)]
/// General Error type, used to capture all kinds of common errors. Can be used to respond to requests
pub enum Error {
    #[error("Not found")]
    NotFound,
    #[error("Bad Request: {0}")]
    BadRequest(&'static str),
    #[error("JWE Error: {0}")]
    Jwe(#[from] JwtError),
    #[error("Postgres Error: {0}")]
    Postgres(#[from] postgres::Error),
    #[error("Reqwest Error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("JSON Error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Parse Error: {0}")]
    Parse(#[from] strum::ParseError),
    #[error("Template Error: {0}")]
    Template(#[from] tera::Error),
}

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for Error {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        use Error::*;
        let (body, status) = match &self {
            NotFound => (json!({"error": "NotFound"}), Status::NotFound),
            BadRequest(m) => (
                json!({"error": "BadRequest", "detail": m}),
                Status::BadRequest,
            ),
            Jwe(e) => (
                json!({"error": "BadRequest", "detail": format!("{}", e)}),
                Status::BadRequest,
            ),
            Template(e) => (
                json!({"error": "TemplateError", "detail": format!("{}", e)}),
                Status::InternalServerError,
            ),
            _ => return rocket::response::Debug::from(self).respond_to(request),
        };
        Ok(Response::build_from(body.respond_to(request).unwrap())
            .status(status)
            .header(ContentType::JSON)
            .finalize())
    }
}

impl From<id_contact_jwt::Error> for Error {
    fn from(e: id_contact_jwt::Error) -> Self {
        Error::Jwe(JwtError::Jwe(e))
    }
}
