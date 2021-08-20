use crate::config::{Config, RawConfig};
use crate::error::Error;
use crate::session::Session;
use crate::types::{
    platform_token::{FromPlatformJwt, HostToken},
    Credentials, GuestAuthResult,
};
use serde_json;
use lazy_static;
use tera::{Context, Tera};

lazy_static! {
    pub static ref TEMPLATES: Tera =
        { Tera::new("templates/*").expect("Could not load templates") };
    pub static ref TRANSLATIONS: Translations = {
        let f = std::fs::File::open("translations.yml").expect("Could not find translation file");

        serde_yaml::from_reader(f).expect("Could not parse translations file")
    };
}

pub fn collect_credentials(
    guest_auth_results: Vec<GuestAuthResult>,
    config: &Config,
) -> Result<Vec<Credentials>, Error> {
    let credentials: Vec<Credentials> = vec![];

    for guest_auth_result in guest_auth_results.iter() {
        let attributes = match guest_auth_result.auth_result {
            Some(r) => {
                attributes =
                    id_contact_jwt::dangerous_decrypt_auth_result_without_verifying_expiration(
                        &guest_auth_result.auth_result,
                        config.validator(),
                        config.decrypter(),
                    )
                    .ok()
            }
            None => None,
        };

        credentials.push(Credentials {
            name: guest_auth_result.name,
            purpose: guest_auth_result.purpose,
            attributes,
        });
    }

    Ok(credentials)
}

pub enum CredentialRenderType {
    Json,
    Html,
    HtmlPage,
}

pub fn render_credentials(
    credentials: Vec<Credentials>,
    render_type: CredentialRenderType,
) -> Result<String, Error> {
    let mut context = Context::new();
    let translations: Translations = TRANSLATIONS.clone();

    context.insert("translations", &translations);
    context.insert("credentials", &credentials);

    match render_type {
        Json => serde_json::to_string(&credentials),
        Html => TEMPLATES.render("credentials.html", &context)?,
        HtmlPage => TEMPLATES.render("base.html", &context)?,
    }
}

#[cfg(feature = "session_db")]
pub async fn get_credentials_for_host(
    host_token: String,
    config: &Config,
    db: SessionDBConn,
) -> Result<Credentials, Error> {
    let host_token = HostToken::from_platform_jwt(&host_token, config.validator())?;
    let sessions: Vec<Session> = Session::find_by_room_id(host_token.room_id, &db).await?;

    let guest_auth_results = sessions.map(|session: Session| GuestAuthResult {
        purpose: Some(session.purpose),
        name: Some(session.guest_token.name),
        auth_result: session.auth_result,
    })?;

    collect_credentials(guest_auth_results, config: &Config)
}

#[cfg(test)]
mod tests {
    use super::*;

    use id_contact_jwt::{sign_and_encrypt_auth_result, EncryptionKeyConfig, SignKeyConfig};
    use std::collections::HashMap;
    use std::convert::TryFrom;

    use id_contact_proto::{AuthResult, AuthStatus};
    use josekit::{
        jwe::{JweDecrypter, JweEncrypter},
        jws::{JwsSigner, JwsVerifier},
    };

    const EC_PUBKEY: &str = r"
    type: EC
    key: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZLquEijJ7cP7K9qIHG7EvCTph53N
        4nz61OgeuZWdvM7LyBVXuW53nY+b6NJmophgcZHqzSiLbk+jPvIGvVUxzQ==
        -----END PUBLIC KEY-----
    ";

    const EC_PRIVKEY: &str = r"
    type: EC
    key: |
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJdHGkAfKUVshsNPQ
        5UA9sNCf74eALrLrtBQE1nDFlv+hRANCAARkuq4SKMntw/sr2ogcbsS8JOmHnc3i
        fPrU6B65lZ28zsvIFVe5bnedj5vo0maimGBxkerNKItuT6M+8ga9VTHN
        -----END PRIVATE KEY-----
    ";

    #[test]
    fn roundtrip_test_ec() {
        let enc_config: EncryptionKeyConfig = serde_yaml::from_str(EC_PUBKEY).unwrap();
        let dec_config: EncryptionKeyConfig = serde_yaml::from_str(EC_PRIVKEY).unwrap();

        let decrypter = Box::<dyn JweDecrypter>::try_from(dec_config).unwrap();
        let encrypter = Box::<dyn JweEncrypter>::try_from(enc_config).unwrap();

        let sig_config: SignKeyConfig = serde_yaml::from_str(EC_PRIVKEY).unwrap();
        let ver_config: SignKeyConfig = serde_yaml::from_str(EC_PUBKEY).unwrap();

        let signer = Box::<dyn JwsSigner>::try_from(sig_config).unwrap();
        let validator = Box::<dyn JwsVerifier>::try_from(ver_config).unwrap();

        let mut test_attributes: HashMap<String, String> = HashMap::new();

        test_attributes.insert("age".to_string(), "42".to_string());
        test_attributes.insert("email".to_string(), "hd@example.com".to_string());

        let in_result = AuthResult {
            status: AuthStatus::Succes,
            attributes: Some(test_attributes),
            session_url: None,
        };
        let jwe =
            sign_and_encrypt_auth_result(&in_result, signer.as_ref(), encrypter.as_ref()).unwrap();

        let guest_auth_results = vec![GuestAuthResult {
            purpose: Some("test_purpose".to_string()),
            name: Some("Henk Dieter".to_string()),
            auth_result: Some(jwe),
        }];

        let config: Config = Config::try_from(RawConfig {
            internal_url: "https://example.com".to_string(),
            external_url: None,
            decrypter,
            validator,
        })
        .unwrap();

        let credentials = collect_credentials(guest_auth_results, &config);
        let out_result = render_credentials(credentials, CredentialRenderType::Html).unwrap();

        let result: &str = "iets van html";

        assert_eq!(result, out_result);
    }
}
