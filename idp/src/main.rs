mod session;
mod users;

use std::str::FromStr;

use askama::Template;
use axum::{
    Form, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use color_eyre::Result;
use color_eyre::eyre::Context;
use serde::Deserialize;
use session::UserSession;
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use tracing::{error, info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

const SESSION_ID_COOKIE_NAME: &str = "IDP_SESSION_ID";

#[derive(Clone)]
struct Db {
    pool: sqlx::Pool<sqlx::Sqlite>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let opts = SqliteConnectOptions::from_str("db.sqlite")
        .unwrap()
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(opts)
        .await
        .wrap_err("connecting to db")?;

    sqlx::migrate!()
        .run(&pool)
        .await
        .wrap_err("running migrations")?;

    let app = Router::<Db>::new()
        .route("/style.css", get(style_css))
        .route("/", get(root))
        .route("/signup", get(signup).post(signup_post))
        .route("/login", get(login).post(login_post))
        .route("/users", get(users))
        .with_state(Db { pool });

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .wrap_err("binding listener")?;
    info!(?addr, "Starting server");
    axum::serve(listener, app).await.wrap_err("serving app")
}

async fn style_css() -> impl IntoResponse {
    let header = [(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/css; charset=utf-8"),
    )];
    (header, include_str!("../templates/style.css"))
}

async fn root(session: UserSession) -> impl IntoResponse {
    #[derive(askama::Template)]
    #[template(path = "index.html")]
    struct Data {
        username: Option<String>,
    }

    Html(
        Data {
            username: session.0.map(|user| user.username),
        }
        .render()
        .unwrap(),
    )
}

#[derive(askama::Template)]
#[template(path = "signup.html")]
struct SignupTemplate {
    already_exists: bool,
}

#[axum::debug_handler]
async fn signup() -> impl IntoResponse {
    Html(
        SignupTemplate {
            already_exists: false,
        }
        .render()
        .unwrap(),
    )
}

#[derive(askama::Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: bool,
}

#[axum::debug_handler]
async fn login() -> impl IntoResponse {
    Html(LoginTemplate { error: false }.render().unwrap())
}

#[axum::debug_handler]
async fn users(State(db): State<Db>) -> Result<impl IntoResponse, Response> {
    let users = users::all_user_names(&db).await.map_err(|err| {
        error!(?err, "Failed to fetch users");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    #[derive(askama::Template)]
    #[template(path = "users.html")]
    struct Data {
        users: Vec<String>,
    }

    Ok(Html(Data { users }.render().unwrap()))
}

#[derive(Deserialize)]
struct UsernamePasswordForm {
    username: String,
    password: String,
}

async fn make_session_cookie_for_user(db: &Db, user_id: i64) -> Result<Cookie<'static>, Response> {
    let session = session::create_session(&db, user_id).await.map_err(|err| {
        error!(?err, "Failed to create session for user");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    Ok(Cookie::build((SESSION_ID_COOKIE_NAME, session.0))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .expires(axum_extra::extract::cookie::Expiration::DateTime(
            time::OffsetDateTime::now_utc()
                .checked_add(time::Duration::days(30))
                .unwrap(),
        ))
        .build())
}

async fn signup_post(
    State(db): State<Db>,
    jar: CookieJar,
    Form(signup): Form<UsernamePasswordForm>,
) -> Result<impl IntoResponse, Response> {
    let user = users::create_user(&db, signup.username, signup.password)
        .await
        .map_err(|err| {
            error!(?err, "Failed to create user");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let Some(user) = user else {
        return Err(Html(
            SignupTemplate {
                already_exists: true,
            }
            .render()
            .unwrap(),
        )
        .into_response());
    };

    let session_id = make_session_cookie_for_user(&db, user.id).await?;

    Ok((jar.add(session_id), Redirect::to("/")))
}

async fn login_post(
    State(db): State<Db>,
    jar: CookieJar,
    Form(login): Form<UsernamePasswordForm>,
) -> Result<impl IntoResponse, Response> {
    let user = users::authenticate_user(&db, login.username, login.password)
        .await
        .map_err(|err| {
            error!(?err, "Failed to create user");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let Some(user) = user else {
        return Err(Html(LoginTemplate { error: true }.render().unwrap()).into_response());
    };

    let session_id = make_session_cookie_for_user(&db, user.id).await?;

    Ok((jar.add(session_id), Redirect::to("/")))
}
