use crate::config::Config;
use crate::error::Error;
#[cfg(feature = "session_db")]
use crate::session::{Session, SessionDBConn};
#[cfg(feature = "session_db")]
use crate::types::platform_token::{FromPlatformJwt, HostToken};
use crate::types::{Credentials, GuestAuthResult};
use lazy_static;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use tera::{Context, Tera};

#[derive(Serialize, Deserialize, Clone)]
pub struct Translations(HashMap<String, String>);

lazy_static! {
    pub static ref TEMPLATES: Tera = Tera::new("templates/*").expect("Could not load templates");
    pub static ref TRANSLATIONS: Translations = {
        let f = std::fs::File::open("translations.yml").expect("Could not find translation file");

        serde_yaml::from_reader(f).expect("Could not parse translations file")
    };
}

pub fn collect_credentials(
    guest_auth_results: &Vec<GuestAuthResult>,
    config: &Config,
) -> Result<Vec<Credentials>, Error> {
    let mut credentials: Vec<Credentials> = vec![];

    for guest_auth_result in guest_auth_results.iter() {
        if let Some(result) = &guest_auth_result.auth_result {
            if let Some(attributes) =
                id_contact_jwt::dangerous_decrypt_auth_result_without_verifying_expiration(
                    result,
                    config.validator(),
                    config.decrypter(),
                )?
                .attributes
            {
                credentials.push(Credentials {
                    name: guest_auth_result.name.clone(),
                    purpose: guest_auth_result.purpose.clone(),
                    attributes,
                });
            }
        };
    }

    Ok(credentials)
}

#[derive(PartialEq)]
pub enum CredentialRenderType {
    Json,
    Html,
    HtmlPage,
}

#[derive(Serialize)]
pub struct SortedCredentials {
    pub purpose: Option<String>,
    pub name: Option<String>,
    pub attributes: Vec<(String, String)>,
}

impl From<Credentials> for SortedCredentials {
    fn from(credentials: Credentials) -> Self {
        let mut attributes = credentials
            .attributes
            .into_iter()
            .collect::<Vec<(String, String)>>();

        attributes.sort_by(|x, y| x.0.cmp(&y.0));

        SortedCredentials {
            purpose: credentials.purpose,
            name: credentials.name,
            attributes,
        }
    }
}

pub fn render_credentials(
    credentials: Vec<Credentials>,
    render_type: CredentialRenderType,
) -> Result<String, Error> {
    if render_type == CredentialRenderType::Json {
        return Ok(serde_json::to_string(&credentials)?);
    }

    let mut context = Context::new();
    let translations: Translations = TRANSLATIONS.clone();

    let sorted_credentials: Vec<SortedCredentials> = credentials
        .into_iter()
        .map(SortedCredentials::from)
        .collect();

    context.insert("translations", &translations);
    context.insert("credentials", &sorted_credentials);

    if render_type == CredentialRenderType::HtmlPage {
        return Ok(TEMPLATES.render("base.html", &context)?);
    };

    Ok(TEMPLATES.render("credentials.html", &context)?)
}

#[cfg(feature = "session_db")]
pub async fn get_credentials_for_host(
    host_token: String,
    config: &Config,
    db: SessionDBConn,
) -> Result<Vec<Credentials>, Error> {
    let host_token = HostToken::from_platform_jwt(
        &host_token,
        config.auth_during_comm_config().host_validator(),
    )?;
    let sessions: Vec<Session> = Session::find_by_room_id(host_token.room_id, &db).await?;

    let guest_auth_results = sessions
        .into_iter()
        .map(|session: Session| GuestAuthResult {
            purpose: Some(session.purpose),
            name: Some(session.guest_token.name),
            auth_result: session.auth_result,
        })
        .collect::<Vec<GuestAuthResult>>();

    collect_credentials(&guest_auth_results, config)
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

    fn remove_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

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

        let config: Config = Config {
            internal_url: "https://example.com".to_string(),
            external_url: None,
            decrypter,
            validator,
        };

        let credentials = collect_credentials(&guest_auth_results, &config).unwrap();
        let out_result = render_credentials(credentials, CredentialRenderType::Html).unwrap();
        let result: &str = "<section><h4>HenkDieter</h4><dl><dt>age</dt><dd>42</dd><dt>E-mailadres</dt><dd>hd@example.com</dd></dl></section>";

        assert_eq!(remove_whitespace(result), remove_whitespace(&out_result));

        let credentials = collect_credentials(&guest_auth_results, &config).unwrap();
        let out_result = render_credentials(credentials, CredentialRenderType::HtmlPage).unwrap();
        let result: &str = "<!doctypehtml><htmllang=\"en\"><head><metacharset=\"utf-8\"><metaname=\"viewport\"content=\"width=device-width,initial-scale=1\"><title>IDContactgegevens</title></head><body><main><divclass=\"attributes\"><div><h4>Geverifieerdegegevens</h4><section><h4>HenkDieter</h4><dl><dt>age</dt><dd>42</dd><dt>E-mailadres</dt><dd>hd@example.com</dd></dl></section></div></div></main></body></html>";

        assert_eq!(remove_whitespace(result), remove_whitespace(&out_result));

        let credentials = collect_credentials(&guest_auth_results, &config).unwrap();
        let rendered = render_credentials(credentials, CredentialRenderType::Json).unwrap();
        let result: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let expected = serde_json::json! {
            [{
                "purpose":"test_purpose",
                "name":"Henk Dieter",
                "attributes":{"age":"42","email":"hd@example.com"}}
            ]
        };

        assert_eq!(result, expected);
    }
}
