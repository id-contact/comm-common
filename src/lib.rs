/// Common configuration mechanisms
pub mod config;
/// Error type with responder implementation
pub mod error;
/// JWT signing functionality
pub mod jwt;
#[cfg(feature = "session_db")]
/// Database manipulation code for keeping track of sessions based on platform tokens
pub mod session;
/// Common types
pub mod types;
/// Utilities
pub mod util;

pub mod prelude {
    pub use crate::config::Config;
    pub use crate::error::Error;
    pub use crate::jwt::sign_auth_select_params;
    #[cfg(feature = "session_db")]
    pub use crate::session::{Session, SessionDBConn};
    pub use crate::types::StartRequest;
    pub use crate::types::{AuthResultSet, AuthSelectParams, GuestAuthResult};
    pub use crate::util::random_string;

    #[cfg(feature = "platform_token")]
    pub use crate::types::{FromPlatformJwt, GuestToken, HostToken};
}
