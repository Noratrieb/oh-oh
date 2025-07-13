use std::time::Duration;

use crate::Db;
use color_eyre::{Result, eyre::Context};
use rand_core::RngCore;

pub fn generate_string(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    rand_core::OsRng.fill_bytes(&mut bytes);
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
}

pub async fn insert_oauth_client(
    db: &Db,
    app_name: &str,
    redirect_uri: &str,
    client_type: &str,
) -> Result<()> {
    let client_id = generate_string(10);
    let client_secret = generate_string(20);

    sqlx::query(
        "insert into oauth_clients (app_name, client_id, client_secret, redirect_uri, client_type)\
        values (?, ?, ?, ?, ?)",
    )
    .bind(app_name)
    .bind(client_id)
    .bind(client_secret)
    .bind(redirect_uri)
    .bind(client_type)
    .execute(&db.pool)
    .await
    .wrap_err("inserting oauth client")?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct OAuthClient {
    pub app_name: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub client_type: String,
}

pub async fn list_oauth_clients(db: &Db) -> Result<Vec<OAuthClient>> {
    sqlx::query_as(
        "select app_name, client_id, client_secret, redirect_uri, client_type from oauth_clients",
    )
    .fetch_all(&db.pool)
    .await
    .wrap_err("fetching oauth clients")
}

pub async fn insert_code(db: &Db, code: &str, client_id: &str, user_id: i64) -> Result<()> {
    sqlx::query(
        "insert into oauth_codes (code, client_id, created_time_ms, user_id)\
        values (?, ?, ?, ?)",
    )
    .bind(code)
    .bind(client_id)
    .bind(jiff::Timestamp::now().as_millisecond())
    .bind(user_id)
    .execute(&db.pool)
    .await
    .wrap_err("inserting oauth client")?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct OAuthCode {
    pub user_id: i64,
}

pub async fn find_code(
    db: &Db,
    code: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<Option<OAuthCode>> {
    let min_created_time_ms = jiff::Timestamp::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap()
        .as_millisecond();
    let result = sqlx::query_as::<_, OAuthCode>(
        "select user_id from oauth_codes \
        inner join oauth_clients on oauth_clients.client_id = oauth_codes.client_id and oauth_clients.client_secret = ? \
        where code = ? and oauth_codes.client_id = ? and created_time_ms > ? and used = 0",
    )
    .bind(client_secret)
    .bind(code)
    .bind(client_id)
    .bind(min_created_time_ms)
    .fetch_one(&db.pool)
    .await;
    match result {
        Ok(code) => Ok(Some(code)),
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Err(e) => Err(e).wrap_err("failed to fetch code"),
    }
}

pub async fn mark_code_as_used(db: &Db, code: &str) -> Result<()> {
    sqlx::query("update oauth_codes set used = 1 where code = ?")
        .bind(code)
        .execute(&db.pool)
        .await
        .wrap_err("inserting oauth client")?;
    Ok(())
}
