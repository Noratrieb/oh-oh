use color_eyre::{Result, eyre::Context};

use crate::Db;

#[derive(sqlx::FromRow)]
pub struct User {
    pub id: i64,
    #[expect(dead_code)]
    pub username: String,
}

#[derive(sqlx::FromRow)]
pub struct UserWithPassword {
    pub id: i64,
    pub username: String,
    pub password: String,
}

fn hash_password(password: &str) -> String {
    use password_hash::PasswordHasher;
    let salt = password_hash::SaltString::generate(&mut rand_core::OsRng);
    let argon2 = argon2::Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(hash) = password_hash::PasswordHash::parse(stored_hash, password_hash::Encoding::B64)
    else {
        return false;
    };

    hash.verify_password(&[&argon2::Argon2::default()], password)
        .is_ok()
}

pub async fn create_user(db: &Db, username: String, password: String) -> Result<Option<User>> {
    let password = tokio::task::spawn_blocking(move || hash_password(&password)).await?;

    let result = sqlx::query_as::<_, User>(
        "insert into users (username, password) values (?, ?) RETURNING *",
    )
    .bind(username)
    .bind(password)
    .fetch_one(&db.pool)
    .await;

    match result {
        Ok(user) => Ok(Some(user)),
        Err(sqlx::Error::Database(db)) if db.kind() == sqlx::error::ErrorKind::UniqueViolation => {
            Ok(None)
        }
        Err(err) => Err(err).wrap_err("creating user"),
    }
}

pub async fn authenticate_user(
    db: &Db,
    username: String,
    password: String,
) -> Result<Option<User>> {
    let user_result = sqlx::query_as::<_, UserWithPassword>(
        "select id, username, password from users where username = ?",
    )
    .bind(username)
    .fetch_one(&db.pool)
    .await;

    let user = match user_result {
        Ok(user) => user,
        Err(sqlx::Error::RowNotFound) => return Ok(None),
        Err(e) => return Err(e).wrap_err("failed to fetch user"),
    };

    let is_ok =
        tokio::task::spawn_blocking(move || verify_password(&password, &user.password)).await?;

    if !is_ok {
        return Ok(None);
    }

    Ok(Some(User {
        id: user.id,
        username: user.username,
    }))
}

pub async fn all_user_names(db: &Db) -> Result<Vec<String>> {
    #[derive(sqlx::FromRow)]
    struct User {
        username: String,
    }

    Ok(sqlx::query_as::<_, User>("select username from users")
        .fetch_all(&db.pool)
        .await
        .wrap_err("fetching users")?
        .into_iter()
        .map(|user| user.username)
        .collect())
}
