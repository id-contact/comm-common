use std::{convert::TryFrom, str::FromStr};

use crate::config::Config;
use crate::error::Error;

use reqwest::header::AUTHORIZATION;
use rocket::{
    fairing::{AdHoc, Fairing},
    http::{Cookie, CookieJar, SameSite},
    outcome::IntoOutcome,
    request::{self, FromRequest, Request},
    response::Redirect,
};
use rocket_oauth2::{OAuth2, TokenResponse};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct LoginUrl {
    pub login_url: String,
}

#[derive(Debug, strum_macros::EnumString)]
pub enum AuthProvider {
    Google,
    Microsoft,
}

impl AuthProvider {
    pub fn fairing(&self) -> impl Fairing {
        match self {
            AuthProvider::Google => AdHoc::on_ignite("Auth", |rocket| async {
                rocket
                    .mount("/", rocket::routes![login_google, redirect_google, logout_generic])
                    .attach(OAuth2::<Google>::fairing("google"))
            }),
            AuthProvider::Microsoft => AdHoc::on_ignite("Auth", |rocket| async {
                rocket
                    .mount("/", rocket::routes![login_microsoft, redirect_microsoft, logout_generic])
                    .attach(OAuth2::<Microsoft>::fairing("microsoft"))
            }),
        }
    }
}

impl TryFrom<String> for AuthProvider {
    type Error = Error;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Ok(AuthProvider::from_str(&name)?)
    }
}

pub struct TokenCookie(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for TokenCookie {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<TokenCookie, Error> {
        request
            .cookies()
            .get_private("token")
            .and_then(|c| c.value().parse().ok())
            .map(TokenCookie)
            .or_forward(())
    }
}

struct Google;

#[rocket::get("/auth/login?<redirect>")]
fn login_google(redirect: String, oauth2: OAuth2<Google>, cookies: &CookieJar<'_>) -> Redirect {
    cookies.add_private(
        Cookie::build("redirect", redirect)
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .finish(),
    );

    oauth2.get_redirect(cookies, &["profile"]).unwrap()
}

#[rocket::get("/auth/redirect")]
async fn redirect_google(
    token: TokenResponse<Google>,
    cookies: &CookieJar<'_>,
) -> Result<Redirect, Error> {
    redirect_generic(token, cookies).await
}

#[derive(serde::Deserialize)]
struct GoogleUserInfo {
    #[serde(default)]
    sub: String,
}

// Currently only checks whether we can actually login with the provided cookie
async fn check_token_google(token: TokenCookie) -> Result<bool, Error> {
    let user_info: GoogleUserInfo = reqwest::Client::builder()
        .build()?
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .header(AUTHORIZATION, format!("Bearer {}", token.0))
        .send()
        .await?
        .json()
        .await?;

    Ok(!user_info.sub.is_empty())
}

struct Microsoft;

#[rocket::get("/auth/login?<redirect>")]
fn login_microsoft(
    redirect: String,
    oauth2: OAuth2<Microsoft>,
    cookies: &CookieJar<'_>,
) -> Redirect {
    cookies.add_private(
        Cookie::build("redirect", redirect)
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .finish(),
    );

    oauth2.get_redirect(cookies, &["user.read"]).unwrap()
}

#[rocket::get("/auth/redirect")]
async fn redirect_microsoft(
    token: TokenResponse<Microsoft>,
    cookies: &CookieJar<'_>,
) -> Result<Redirect, Error> {
    redirect_generic(token, cookies).await
}

#[derive(serde::Deserialize)]
struct MicrosoftUserInfo {
    #[serde(default, rename = "displayName")]
    display_name: String,
}

// Currently only checks whether we can actually login with the provided cookie
async fn check_token_microsoft(token: TokenCookie) -> Result<bool, Error> {
    let user_info: MicrosoftUserInfo = reqwest::Client::builder()
        .build()?
        .get("https://graph.microsoft.com/v1.0/me")
        .header(AUTHORIZATION, format!("Bearer {}", token.0))
        .send()
        .await?
        .json()
        .await?;

    Ok(!user_info.display_name.is_empty())
}

pub async fn check_token(token: TokenCookie, config: &Config) -> Result<bool, Error> {
    match config.auth_provider() {
        Some(AuthProvider::Google) => check_token_google(token).await,
        Some(AuthProvider::Microsoft) => check_token_microsoft(token).await,
        None => Err(Error::Forbidden("No auth provider configured")),
    }
}

async fn redirect_generic<T>(
    token: TokenResponse<T>,
    cookies: &CookieJar<'_>,
) -> Result<Redirect, Error> {
    cookies.add_private(
        Cookie::build("token", token.access_token().to_owned())
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .finish(),
    );

    match cookies.get_private("redirect") {
        Some(redirect_to) => {
            cookies.remove_private(Cookie::named("redirect"));
            Ok(Redirect::to(redirect_to.value().to_owned()))
        }
        None => Ok(Redirect::to("/")),
    }
}

#[rocket::post("/auth/logout")]
async fn logout_generic(cookies: &CookieJar<'_>) -> Result<(), Error> {
    cookies.remove_private(Cookie::named("token"));
    Ok(())
}
