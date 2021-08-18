use core::str;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct StartRequest {
    pub purpose: String,
    pub auth_method: String,
}

/// Parameters expected by the auth-select widget
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthSelectParams {
    /// The session purpose
    pub purpose: String,
    /// The start url to redirect the user to on authentication success
    pub start_url: String,
    /// The communication method's display name
    pub display_name: String,
}

#[derive(Serialize, Debug)]
pub struct GuestAuthResult {
    pub attributes: Option<HashMap<String, String>>,
    pub name: String,
}

pub type AuthResultSet = HashMap<String, GuestAuthResult>;

#[cfg(feature = "platform_token")]
pub use platform_token::*;

#[cfg(feature = "platform_token")]
pub mod platform_token {
    use crate::jwt::JwtError;
    use core::str;
    use josekit::jws::JwsVerifier;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use strum_macros::{EnumString, ToString};

    #[derive(Deserialize, Debug, Serialize, ToString, Clone, EnumString)]
    #[strum(serialize_all = "snake_case")]
    pub enum SessionDomain {
        #[serde(rename = "user")]
        User,
        #[serde(rename = "guest")]
        Guest,
    }

    #[derive(Deserialize, Debug)]
    pub struct HostToken {
        pub id: String,
        pub domain: SessionDomain,
        #[serde(rename = "roomId")]
        pub room_id: String,
        pub instance: String,
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub struct GuestToken {
        pub id: String,
        pub domain: SessionDomain,
        #[serde(rename = "redirectUrl")]
        pub redirect_url: String,
        pub name: String,
        #[serde(rename = "roomId")]
        pub room_id: String,
        pub instance: String,
    }

    pub trait FromPlatformJwt: Sized + DeserializeOwned {
        fn from_platform_jwt(jwt: &str, validator: &dyn JwsVerifier) -> Result<Self, JwtError> {
            let (payload, _) = josekit::jwt::decode_with_verifier(jwt, validator)?;
            let claim = payload
                .claim("payload")
                .ok_or(JwtError::InvalidStructure("payload"))?;
            let payload = serde_json::from_value(claim.clone())?;
            Ok(payload)
        }
    }

    impl FromPlatformJwt for GuestToken {}

    impl FromPlatformJwt for HostToken {}
}
