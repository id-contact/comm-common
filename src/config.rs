use crate::error::Error;

use id_contact_jwt::{EncryptionKeyConfig, SignKeyConfig};
use josekit::{jwe::JweDecrypter, jws::JwsVerifier};
use serde::Deserialize;

use std::convert::TryFrom;

#[cfg(feature = "auth_during_comm")]
pub (crate) use self::auth_during_comm::{AuthDuringCommConfig, RawAuthDuringCommConfig};

/// Configuration paramters as read directly fom config.toml file.
#[derive(Deserialize, Debug)]
pub struct RawConfig {
    /// Internal-facing URL
    internal_url: String,
    /// External-facing URL. Defaults to Internal-facing if not set
    external_url: Option<String>,

    /// Private key used to decrypt ID Contact JWEs
    decryption_privkey: EncryptionKeyConfig,
    /// Public key used to sign ID Contact JWSs
    signature_pubkey: SignKeyConfig,

    #[cfg(feature = "auth_during_comm")]
    #[serde(flatten)]
    /// Configuration specific for auth during comm
    auth_during_comm_config: RawAuthDuringCommConfig,
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "RawConfig")]
pub struct Config {
    pub internal_url: String,
    pub external_url: Option<String>,

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
    #[cfg(feature = "auth_during_comm")]
    pub fn auth_during_comm_config(&self) -> &AuthDuringCommConfig {
        &self.auth_during_comm_config
    }
}

#[cfg(feature = "auth_during_comm")]
mod auth_during_comm {
    use id_contact_jwt::SignKeyConfig;
    use serde::Deserialize;
    use std::convert::TryFrom;

    use josekit::jws::{alg::hmac::HmacJwsAlgorithm, JwsSigner, JwsVerifier};

    use crate::error::Error;

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
        /// Secret for verifying guest tokens
        guest_signature_secret: String,
        /// Secret for verifying host tokens
        host_signature_secret: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(try_from = "RawAuthDuringCommConfig")]
    pub struct AuthDuringCommConfig {
        pub(crate) core_url: String,
        pub(crate) widget_url: String,
        pub(crate) display_name: String,
        pub(crate) widget_signer: Box<dyn JwsSigner>,
        pub(crate) guest_validator: Box<dyn JwsVerifier>,
        pub(crate) host_validator: Box<dyn JwsVerifier>,
    }

    // This tryfrom can be removed once try_from for fields lands in serde
    impl TryFrom<RawAuthDuringCommConfig> for AuthDuringCommConfig {
        type Error = Error;
        fn try_from(raw_config: RawAuthDuringCommConfig) -> Result<AuthDuringCommConfig, Error> {
            let guest_validator = HmacJwsAlgorithm::Hs256
                .verifier_from_bytes(raw_config.guest_signature_secret)
                .unwrap();
            let host_validator = HmacJwsAlgorithm::Hs256
                .verifier_from_bytes(raw_config.host_signature_secret)
                .unwrap();

            Ok(AuthDuringCommConfig {
                core_url: raw_config.core_url,
                widget_url: raw_config.widget_url,
                display_name: raw_config.display_name,

                widget_signer: Box::<dyn JwsSigner>::try_from(raw_config.widget_signing_privkey)?,
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

        pub fn guest_validator(&self) -> &dyn JwsVerifier {
            self.guest_validator.as_ref()
        }

        pub fn host_validator(&self) -> &dyn JwsVerifier {
            self.host_validator.as_ref()
        }
    }
}
