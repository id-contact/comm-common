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
