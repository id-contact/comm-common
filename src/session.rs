use std::str::FromStr;

use crate::{
    error::Error,
    types::{GuestToken, SessionDomain},
};
use rocket_sync_db_pools::postgres;
use serde::{Deserialize, Serialize};

pub use db::*;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Session {
    /// The guest token associated with this session
    pub guest_token: GuestToken,
    /// The autheniction result. `None` if none was received yet
    pub auth_result: Option<String>,
    /// ID used to match incoming attributes with this session
    pub attr_id: String,
    /// Session purpose
    pub purpose: String,
}

impl Session {
    /// Create a new session
    pub fn new(guest_token: GuestToken, attr_id: String, purpose: String) -> Self {
        Self {
            attr_id,
            purpose,
            guest_token,
            auth_result: None,
        }
    }

    /// Persist a sessions. This can only be done for newly created sessions,
    /// as the session id is unique.
    pub async fn persist(&self, db: &SessionDBConn) -> Result<(), Error> {
        let this = self.clone();
        let res = db
            .run(move |c| {
                c.execute(
                    "INSERT INTO session (
                session_id,
                room_id,
                domain,
                redirect_url,
                purpose,
                name,
                instance,
                attr_id,
                auth_result,
                last_activity
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now());",
                    &[
                        &this.guest_token.id,
                        &this.guest_token.room_id,
                        &this.guest_token.domain.to_string(),
                        &this.guest_token.redirect_url,
                        &this.purpose,
                        &this.guest_token.name,
                        &this.guest_token.instance,
                        &this.attr_id,
                        &this.auth_result,
                    ],
                )
            })
            .await;

        res.map_err(|e| {
            if let Some(&postgres::error::SqlState::UNIQUE_VIOLATION) = e.code() {
                Error::BadRequest("A session with that ID already exists")
            } else {
                Error::from(e)
            }
        })?;
        Ok(())
    }

    /// Register an authentication result with a session. Fails if the session
    /// already contains an authentication result.
    pub async fn register_auth_result(
        attr_id: String,
        auth_result: String,
        db: &SessionDBConn,
    ) -> Result<(), Error> {
        let n = db
            .run(move |c| {
                c.execute(
                    "UPDATE session
                    SET (auth_result, last_activity) = ($1, now())
                    WHERE auth_result IS NULL
                    AND attr_id = $2;",
                    &[&auth_result, &attr_id],
                )
            })
            .await?;

        match n {
            1 => Ok(()),
            _ => Err(Error::NotFound),
        }
    }

    /// Find sessions by room ID
    pub async fn find_by_room_id(room_id: String, db: &SessionDBConn) -> Result<Vec<Self>, Error> {
        let sessions = db
            .run(move |c| -> Result<Vec<Session>, Error> {
                let rows = c.query(
                    "
                    UPDATE session
                    SET last_activity = now()
                    WHERE room_id = $1
                    RETURNING
                        session_id,
                        room_id,
                        domain,
                        redirect_url,
                        purpose,
                        name,
                        instance,
                        attr_id,
                        auth_result
                    ",
                    &[&room_id],
                )?;
                if rows.is_empty() {
                    return Err(Error::NotFound);
                }
                rows.into_iter()
                    .map(|r| -> Result<_, Error> {
                        let domain = SessionDomain::from_str(r.get("domain"))?;
                        let guest_token = GuestToken {
                            id: r.get("session_id"),
                            room_id: r.get("room_id"),
                            domain,
                            redirect_url: r.get("redirect_url"),
                            name: r.get("name"),
                            instance: r.get("instance"),
                        };
                        Ok(Session {
                            purpose: r.get("purpose"),
                            guest_token,
                            attr_id: r.get("attr_id"),
                            auth_result: r.get("auth_result"),
                        })
                    })
                    .collect()
            })
            .await?;

        Ok(sessions)
    }
}

/// Remove all sessions that have been inactive for an hour or more
pub async fn clean_db(db: &SessionDBConn) -> Result<(), Error> {
    db.run(move |c| {
        c.execute(
            "DELETE FROM session WHERE last_activity < now() - INTERVAL '1 hour'",
            &[],
        )
    })
    .await?;
    Ok(())
}
#[cfg(not(test))]
mod db {
    use rocket_sync_db_pools::{database, postgres};

    #[database("session")]
    pub struct SessionDBConn(postgres::Client);
}

#[cfg(test)]
mod db {
    use rocket_sync_db_pools::postgres;
    use std::cell::RefCell;

    #[cfg(test)]
    pub struct SessionDBConn(RefCell<postgres::Client>);

    #[cfg(test)]
    impl SessionDBConn {
        pub fn new(c: postgres::Client) -> Self {
            Self(RefCell::new(c))
        }

        pub async fn run<T: Send, F: Sync + Fn(&mut postgres::Client) -> T>(&self, f: F) -> T {
            f(&mut self.0.borrow_mut())
        }
    }
}

#[cfg(test)]
mod tests {
    use rocket_sync_db_pools::postgres::{self, NoTls};

    use crate::prelude::GuestToken;

    use super::{Session, SessionDBConn};
    fn init_database() -> SessionDBConn {
        let client: postgres::Client =
            postgres::Client::connect("postgresql://tg@localhost:5432/tg", NoTls).unwrap();
        SessionDBConn::new(client)
    }

    #[test]
    fn clean_db_test() {
        let db = init_database();

        const ROOM_ID: &str = "987-654-321";
        const ATTR_ID: &str = "123465789";

        let guest_token = GuestToken {
            id: "123-456-789".to_owned(),
            domain: crate::types::SessionDomain::Guest,
            redirect_url: "idcontact.nl".to_owned(),
            name: "Test Id Contact".to_owned(),
            room_id: ROOM_ID.to_owned(),
            instance: "icontact.nl".to_owned(),
        };

        let s = Session {
            guest_token: guest_token,
            auth_result: None,
            attr_id: ATTR_ID.to_owned(),
            purpose: "test".to_owned(),
        };

        smol::block_on(async {
            s.persist(&db).await.unwrap();
            Session::register_auth_result(
                ATTR_ID.to_owned(),
                "invalid_auth_result".to_owned(),
                &db,
            )
            .await
            .unwrap();

            let sessions = Session::find_by_room_id(ROOM_ID.to_owned(), &db)
                .await
                .unwrap();

            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].auth_result, Some("invalid_auth_result".to_owned()))
        });
    }
}
