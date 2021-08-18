use crate::error::Error;

use id_contact_jwt::{EncryptionKeyConfig, SignKeyConfig};
use josekit::{
    jwe::JweDecrypter,
    jws::{alg::hmac::HmacJwsAlgorithm, JwsSigner, JwsVerifier},
};
use serde::Deserialize;

use std::convert::TryFrom;

#[derive(Deserialize, Debug)]
pub struct RawBaseConfig {
    internal_url: String,
    external_url: String,

    decryption_privkey: EncryptionKeyConfig,
    signature_pubkey: SignKeyConfig,
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "RawBaseConfig")]
pub struct BaseConfig {
    internal_url: String,
    external_url: String,

    decrypter: Box<dyn JweDecrypter>,
    validator: Box<dyn JwsVerifier>,
}

// This tryfrom can be removed once try_from for fields lands in serde
impl TryFrom<RawBaseConfig> for BaseConfig {
    type Error = Error;
    fn try_from(raw_config: RawBaseConfig) -> Result<BaseConfig, Error> {
        Ok(BaseConfig {
            internal_url: raw_config.internal_url,
            external_url: raw_config.external_url,

            decrypter: Box::<dyn JweDecrypter>::try_from(raw_config.decryption_privkey)?,
            validator: Box::<dyn JwsVerifier>::try_from(raw_config.signature_pubkey)?,
        })
    }
}

impl BaseConfig {
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
        &self.external_url
    }
}

#[derive(Deserialize, Debug)]
pub struct RawAuthDuringCommConfig {
    #[serde(flatten)]
    raw_base_config: RawBaseConfig,
    core_url: String,
    widget_url: String,
    display_name: String,
    widget_signing_privkey: SignKeyConfig,
    guest_signature_secret: String,
    host_signature_secret: String,
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "RawAuthDuringCommConfig")]
pub struct AuthDuringCommConfig {
    #[serde(flatten)]
    base_config: BaseConfig,
    core_url: String,
    widget_url: String,
    display_name: String,
    widget_signer: Box<dyn JwsSigner>,
    guest_validator: Box<dyn JwsVerifier>,
    host_validator: Box<dyn JwsVerifier>,
}

// This tryfrom can be removed once try_from for fields lands in serde
impl TryFrom<RawAuthDuringCommConfig> for AuthDuringCommConfig {
    type Error = Error;
    fn try_from(raw_config: RawAuthDuringCommConfig) -> Result<AuthDuringCommConfig, Error> {
        let base_config = BaseConfig::try_from(raw_config.raw_base_config)?;
        let guest_validator = HmacJwsAlgorithm::Hs256
            .verifier_from_bytes(raw_config.guest_signature_secret)
            .unwrap();
        let host_validator = HmacJwsAlgorithm::Hs256
            .verifier_from_bytes(raw_config.host_signature_secret)
            .unwrap();

        Ok(AuthDuringCommConfig {
            base_config,
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
    pub fn base_config(&self) -> &BaseConfig {
        &self.base_config
    }

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
