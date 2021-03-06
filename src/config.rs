use crate::error::Error;

use id_contact_jwt::{EncryptionKeyConfig, SignKeyConfig};
use josekit::{jwe::JweDecrypter, jws::JwsVerifier};
use serde::Deserialize;

use std::convert::TryFrom;

#[cfg(feature = "auth_during_comm")]
pub(crate) use self::auth_during_comm::{AuthDuringCommConfig, RawAuthDuringCommConfig};

/// Configuration paramters as read directly fom config.toml file.
#[derive(Deserialize, Debug)]
pub struct RawConfig {
    /// Internal-facing URL
    internal_url: String,
    /// External-facing URL. Defaults to Internal-facing if not set
    external_url: Option<String>,
    /// Sentry DSN
    sentry_dsn: Option<String>,

    /// Private key used to decrypt ID Contact JWEs
    decryption_privkey: EncryptionKeyConfig,
    /// Public key used to sign ID Contact JWSs
    signature_pubkey: SignKeyConfig,

    #[cfg(feature = "auth_during_comm")]
    #[serde(flatten)]
    /// Configuration specific for auth during comm
    auth_during_comm_config: RawAuthDuringCommConfig,
}

/// configuration container for a typical id-contact communication plugin
#[derive(Debug, Deserialize)]
#[serde(try_from = "RawConfig")]
pub struct Config {
    pub internal_url: String,
    pub external_url: Option<String>,
    pub sentry_dsn: Option<String>,

    pub decrypter: Box<dyn JweDecrypter>,
    pub validator: Box<dyn JwsVerifier>,

    #[cfg(feature = "auth_during_comm")]
    #[serde(flatten)]
    pub auth_during_comm_config: AuthDuringCommConfig,
}

// This tryfrom can be removed once try_from for fields lands in serde
impl TryFrom<RawConfig> for Config {
    type Error = Error;
    fn try_from(raw_config: RawConfig) -> Result<Config, Error> {
        #[cfg(feature = "auth_during_comm")]
        let auth_during_comm_config =
            AuthDuringCommConfig::try_from(raw_config.auth_during_comm_config)?;

        Ok(Config {
            #[cfg(feature = "auth_during_comm")]
            auth_during_comm_config,
            internal_url: raw_config.internal_url,
            external_url: raw_config.external_url,
            sentry_dsn: raw_config.sentry_dsn,

            decrypter: Box::<dyn JweDecrypter>::try_from(raw_config.decryption_privkey)?,
            validator: Box::<dyn JwsVerifier>::try_from(raw_config.signature_pubkey)?,
        })
    }
}

impl Config {
    pub fn decrypter(&self) -> &dyn JweDecrypter {
        self.decrypter.as_ref()
    }

    pub fn validator(&self) -> &dyn JwsVerifier {
        self.validator.as_ref()
    }

    pub fn internal_url(&self) -> &str {
        &self.internal_url
    }

    pub fn external_url(&self) -> &str {
        match &self.external_url {
            Some(external_url) => external_url,
            None => &self.internal_url,
        }
    }

    pub fn sentry_dsn(&self) -> Option<&str> {
        self.sentry_dsn.as_deref()
    }

    #[cfg(feature = "auth_during_comm")]
    pub fn auth_during_comm_config(&self) -> &AuthDuringCommConfig {
        &self.auth_during_comm_config
    }
}

#[cfg(feature = "auth_during_comm")]
mod auth_during_comm {
    use id_contact_jwt::SignKeyConfig;
    use serde::Deserialize;
    use std::{convert::TryFrom, fmt::Debug};

    use josekit::jws::{alg::hmac::HmacJwsAlgorithm, JwsSigner, JwsVerifier};

    use crate::error::Error;

    #[derive(Deserialize)]
    #[serde(from = "String")]
    struct TokenSecret(String);

    impl From<String> for TokenSecret {
        fn from(value: String) -> Self {
            TokenSecret(value)
        }
    }

    impl Debug for TokenSecret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TokenSecret").finish()
        }
    }

    #[derive(Deserialize, Debug)]
    /// Configuration specific for auth during comm
    pub struct RawAuthDuringCommConfig {
        /// URL to reach the ID Contact core directly
        core_url: String,
        /// URL to allow user redirects to the widget
        widget_url: String,
        /// Display name for this plugin, to be presented to user
        display_name: String,
        /// Private key to sign widget parameters
        widget_signing_privkey: SignKeyConfig,
        /// Private key to sign start authenticate requests
        start_auth_signing_privkey: SignKeyConfig,
        /// Key Identifier of start authentication key
        start_auth_key_id: String,
        /// Secret for verifying guest tokens
        guest_signature_secret: TokenSecret,
        /// Secret for verifying host tokens
        host_signature_secret: TokenSecret,
    }

    #[derive(Debug, Deserialize)]
    #[serde(try_from = "RawAuthDuringCommConfig")]
    pub struct AuthDuringCommConfig {
        pub(crate) core_url: String,
        pub(crate) widget_url: String,
        pub(crate) display_name: String,
        pub(crate) widget_signer: Box<dyn JwsSigner>,
        pub(crate) start_auth_signer: Box<dyn JwsSigner>,
        pub(crate) start_auth_key_id: String,
        pub(crate) guest_validator: Box<dyn JwsVerifier>,
        pub(crate) host_validator: Box<dyn JwsVerifier>,
    }

    // This tryfrom can be removed once try_from for fields lands in serde
    impl TryFrom<RawAuthDuringCommConfig> for AuthDuringCommConfig {
        type Error = Error;
        fn try_from(raw_config: RawAuthDuringCommConfig) -> Result<AuthDuringCommConfig, Error> {
            let guest_validator = HmacJwsAlgorithm::Hs256
                .verifier_from_bytes(raw_config.guest_signature_secret.0)
                .unwrap();
            let host_validator = HmacJwsAlgorithm::Hs256
                .verifier_from_bytes(raw_config.host_signature_secret.0)
                .unwrap();

            Ok(AuthDuringCommConfig {
                core_url: raw_config.core_url,
                widget_url: raw_config.widget_url,
                display_name: raw_config.display_name,

                widget_signer: Box::<dyn JwsSigner>::try_from(raw_config.widget_signing_privkey)?,
                start_auth_signer: Box::<dyn JwsSigner>::try_from(
                    raw_config.start_auth_signing_privkey,
                )?,
                start_auth_key_id: raw_config.start_auth_key_id,
                guest_validator: Box::new(guest_validator),
                host_validator: Box::new(host_validator),
            })
        }
    }

    impl AuthDuringCommConfig {
        pub fn core_url(&self) -> &str {
            &self.core_url
        }

        pub fn widget_url(&self) -> &str {
            &self.widget_url
        }

        pub fn display_name(&self) -> &str {
            &self.display_name
        }

        pub fn widget_signer(&self) -> &dyn JwsSigner {
            self.widget_signer.as_ref()
        }

        pub fn start_auth_signer(&self) -> &dyn JwsSigner {
            self.start_auth_signer.as_ref()
        }

        pub fn start_auth_key_id(&self) -> &str {
            &self.start_auth_key_id
        }

        pub fn guest_validator(&self) -> &dyn JwsVerifier {
            self.guest_validator.as_ref()
        }

        pub fn host_validator(&self) -> &dyn JwsVerifier {
            self.host_validator.as_ref()
        }
    }

    #[cfg(test)]
    mod tests {
        use josekit::jws::alg::hmac::HmacJwsAlgorithm;

        use super::TokenSecret;

        #[test]
        fn test_log_hiding() {
            let test_secret = TokenSecret("test1234123412341234123412341234".into());
            assert_eq!(format!("{:?}", test_secret), "TokenSecret");

            // Cannary test for something going wrong in the jose library
            let test_verifier = HmacJwsAlgorithm::Hs256
                .verifier_from_bytes(test_secret.0)
                .unwrap();
            assert_eq!(format!("{:?}", test_verifier), "HmacJwsVerifier { algorithm: Hs256, private_key: PKey { algorithm: \"HMAC\" }, key_id: None }");
        }
    }
}
