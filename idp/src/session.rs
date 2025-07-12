use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use color_eyre::Result;
use color_eyre::eyre::Context;
use rand_core::RngCore;
use tracing::error;

use crate::Db;

#[derive(Debug, sqlx::FromRow)]
pub struct SessionWithUser {
    pub user_id: i64,
    /// unix ms
    #[expect(dead_code)]
    pub created: i64,
    pub username: String,
}

pub struct SessionId(pub String);

pub async fn find_session(db: &Db, session_id: &str) -> Result<Option<SessionWithUser>> {
    let result = sqlx::query_as::<_, SessionWithUser>(
        "select user_id, created, username from sessions left join users on sessions.user_id = users.id where session_id = ?",
    )
    .bind(session_id)
    .fetch_one(&db.pool)
    .await;
    match result {
        Ok(session) => Ok(Some(session)),
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Err(e) => Err(e).wrap_err("failed to fetch session"),
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct SessionForList {
    pub created: i64,
    pub session_public_id: i64,
    pub user_agent: String,
}

pub async fn find_sessions_for_user(db: &Db, user_id: i64) -> Result<Vec<SessionForList>> {
    sqlx::query_as::<_, SessionForList>(
        "select created, session_public_id, user_agent from sessions where user_id = ?",
    )
    .bind(user_id)
    .fetch_all(&db.pool)
    .await
    .wrap_err("failed to fetch sessions for user")
}

pub async fn delete_session(db: &Db, user_id: i64, session_public_id: i64) -> Result<()> {
    sqlx::query("delete from sessions where user_id = ? and session_public_id = ?")
        .bind(user_id)
        .bind(session_public_id)
        .execute(&db.pool)
        .await
        .wrap_err("failed to delete session")?;
    Ok(())
}

pub async fn create_session(db: &Db, user_id: i64, user_agent: &str) -> Result<SessionId> {
    let mut session_id = [0_u8; 32];
    rand_core::OsRng.fill_bytes(&mut session_id);
    let session_id = format!("idpsess_{}", hex::encode(session_id));

    sqlx::query(
        "insert into sessions (session_id, user_id, created, user_agent) values (?, ?, ?, ?)",
    )
    .bind(&session_id)
    .bind(user_id)
    .bind(jiff::Timestamp::now().as_millisecond())
    .bind(user_agent)
    .execute(&db.pool)
    .await
    .wrap_err("inserting new session")?;

    Ok(SessionId(session_id))
}

#[derive(Debug)]
pub struct UserSession(pub Option<SessionWithUser>);

impl FromRequestParts<Db> for UserSession {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        db: &Db,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);

        match jar.get(crate::SESSION_ID_COOKIE_NAME) {
            None => Ok(UserSession(None)),
            Some(cookie) => {
                let sess = find_session(&db, cookie.value()).await;
                match sess {
                    Ok(user) => Ok(UserSession(user)),
                    Err(err) => {
                        error!(?err, "Error fetching session");
                        Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
                    }
                }
            }
        }
    }
}
