pub mod config;
pub mod error;
pub mod jwt;
#[cfg(feature = "platform_token")]
pub mod session;
pub mod types;
pub mod util;

pub mod prelude {
    pub use crate::config::Config;
    pub use crate::error::Error;
    pub use crate::types::StartRequest;
    pub use crate::util::random_string;
    pub use crate::jwt::sign_auth_select_params;
    #[cfg(feature = "platform_token")]
    pub use crate::session::{Session, SessionDBConn};
    pub use crate::types::{
        AuthResultSet, AuthSelectParams, GuestAuthResult, 
    };

    pub use crate::types::{
        GuestToken, HostToken, FromPlatformJwt
    };
}
