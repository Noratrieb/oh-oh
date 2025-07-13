mod session;
mod totp;
mod users;

use std::str::FromStr;

use askama::Template;
use axum::{
    Form, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
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
        .route("/login-2fa", get(login_2fa).post(login_2fa_post))
        .route("/2fa", get(list_2fa))
        .route("/sessions", get(list_sessions))
        .route("/sessions/delete", post(delete_session))
        .route("/2fa/delete", post(delete_2fa))
        .route("/add-totp", get(add_totp).post(add_totp_post))
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

#[derive(askama::Template)]
#[template(path = "add-totp.html")]
struct AddTotpTemplate {
    totp_secret: String,
    error: bool,
}

#[axum::debug_handler]
async fn login() -> impl IntoResponse {
    Html(LoginTemplate { error: false }.render().unwrap())
}

#[derive(askama::Template)]
#[template(path = "login-2fa.html")]
struct Login2faTemplate {
    error: bool,
    reuse: bool,
}

#[axum::debug_handler]
async fn login_2fa() -> impl IntoResponse {
    Html(
        Login2faTemplate {
            error: false,
            reuse: false,
        }
        .render()
        .unwrap(),
    )
}

async fn list_2fa(user: UserSession, State(db): State<Db>) -> Result<impl IntoResponse, Response> {
    let Some(user) = user.0 else {
        return Err(Redirect::to("/").into_response());
    };

    let devices = totp::list_totp_devices(&db, user.user_id)
        .await
        .map_err(|err| {
            error!(?err, "Error fetching totp devices");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    #[derive(askama::Template)]
    #[template(path = "2fa.html")]
    struct Template {
        devices: Vec<totp::TotpDevice>,
    }

    Ok(Html(Template { devices }.render().unwrap()))
}

async fn list_sessions(
    user: UserSession,
    State(db): State<Db>,
) -> Result<impl IntoResponse, Response> {
    let Some(user) = user.0 else {
        return Err(Redirect::to("/").into_response());
    };

    let sessions = session::find_sessions_for_user(&db, user.user_id)
        .await
        .map_err(|err| {
            error!(?err, "Error fetching sessions");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    #[derive(askama::Template)]
    #[template(path = "sessions.html")]
    struct Template {
        sessions: Vec<session::SessionForList>,
    }

    Ok(Html(Template { sessions }.render().unwrap()))
}

#[derive(Deserialize)]
struct DeleteSessionForm {
    session_public_id: i64,
}

async fn delete_session(
    user: UserSession,
    State(db): State<Db>,
    Form(form): Form<DeleteSessionForm>,
) -> Result<impl IntoResponse, Response> {
    let Some(user) = user.0 else {
        return Err(Redirect::to("/").into_response());
    };

    session::delete_session(&db, user.user_id, form.session_public_id)
        .await
        .map_err(|err| {
            error!(?err, "Failed to delete session");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    Ok(Redirect::to("/sessions"))
}

#[derive(Deserialize)]
struct Delete2faForm {
    device_id: i64,
}

async fn delete_2fa(
    user: UserSession,
    State(db): State<Db>,
    Form(form): Form<Delete2faForm>,
) -> Result<impl IntoResponse, Response> {
    let Some(user) = user.0 else {
        return Err(Redirect::to("/").into_response());
    };

    // TODO: This should require 2FA authentication

    totp::delete_totp_device(&db, user.user_id, form.device_id)
        .await
        .map_err(|err| {
            error!(?err, "Failed to delete totp device");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    Ok(Redirect::to("/2fa"))
}

#[axum::debug_handler]
async fn add_totp() -> impl IntoResponse {
    let secret = totp::generate_secret();

    Html(
        AddTotpTemplate {
            totp_secret: secret,
            error: false,
        }
        .render()
        .unwrap(),
    )
}

#[derive(Deserialize)]
struct AddTotpForm {
    name: String,
    code: String,
    secret: String,
}

async fn add_totp_post(
    user: UserSession,
    State(db): State<Db>,
    Form(form): Form<AddTotpForm>,
) -> Result<impl IntoResponse, Response> {
    let Some(user) = user.0 else {
        return Err(Redirect::to("/").into_response());
    };

    let computed = totp::Totp::compute(
        &form.secret,
        totp::Totp::time_step(jiff::Timestamp::now().as_second()),
    );

    if computed.digits != form.code.trim() {
        return Err(Html(
            AddTotpTemplate {
                totp_secret: form.secret,
                error: true,
            }
            .render()
            .unwrap(),
        )
        .into_response());
    }

    totp::insert_totp_device(&db, user.user_id, form.secret, form.name)
        .await
        .map_err(|err| {
            error!(?err, "Error inserting totp device");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    Ok(Redirect::to("/2fa"))
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

async fn make_session_cookie_for_user(
    db: &Db,
    user_id: i64,
    user_agent: &str,
    locked_2fa: bool,
) -> Result<Cookie<'static>, Response> {
    let session = session::create_session(&db, user_id, user_agent, locked_2fa)
        .await
        .map_err(|err| {
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
    headers: HeaderMap,
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

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| str::from_utf8(v.as_bytes()).ok())
        .unwrap_or("unknown");

    let session_id = make_session_cookie_for_user(&db, user.id, user_agent, false).await?;

    Ok((jar.add(session_id), Redirect::to("/")))
}

async fn login_post(
    headers: HeaderMap,
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

    let totp_devices = totp::list_totp_devices(&db, user.id).await.map_err(|err| {
        error!(?err, "Failed to list totp devices");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let locked_2fa = !totp_devices.is_empty();

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| str::from_utf8(v.as_bytes()).ok())
        .unwrap_or("unknown");

    let session_id = make_session_cookie_for_user(&db, user.id, user_agent, locked_2fa).await?;

    let redirect_target = if locked_2fa { "/login-2fa" } else { "/" };

    Ok((jar.add(session_id), Redirect::to(redirect_target)))
}

#[derive(Deserialize)]
struct Login2faForm {
    totp_code: String,
}

async fn login_2fa_post(
    State(db): State<Db>,
    jar: CookieJar,
    Form(form): Form<Login2faForm>,
) -> Result<impl IntoResponse, Response> {
    let now = jiff::Timestamp::now();

    let Some(session_id) = jar.get(crate::SESSION_ID_COOKIE_NAME) else {
        return Err(Redirect::to("/").into_response());
    };

    let session = session::find_locked_session(&db, session_id.value())
        .await
        .map_err(|err| {
            error!(?err, "Failed to find locked session");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let Some(session) = session else {
        return Err(Redirect::to("/").into_response());
    };

    let totp_devices = totp::list_totp_devices(&db, session.user_id)
        .await
        .map_err(|err| {
            error!(?err, "Failed to list totp devices");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let time_step = now.as_second() / 30;
    let used = totp::find_used_totp(&db, session.user_id, time_step)
        .await
        .map_err(|err| {
            error!(?err, "Failed to find used totp");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    if used.has_used > 0 {
        return Err(Html(
            Login2faTemplate {
                error: false,
                reuse: true,
            }
            .render()
            .unwrap(),
        )
        .into_response());
    }

    let code_matches = totp_devices.iter().any(|device| {
        totp::Totp::compute(&device.secret, time_step).digits == form.totp_code.trim()
    });

    if code_matches {
        totp::insert_used_totp_code(&db, session.user_id, time_step)
            .await
            .map_err(|err| {
                error!(?err, "Failed to insert used totp");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
        session::unlock_session(&db, &session.session_id)
            .await
            .map_err(|err| {
                error!(?err, "Failed to unlock session");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
    } else {
        return Err(Html(
            Login2faTemplate {
                error: true,
                reuse: false,
            }
            .render()
            .unwrap(),
        )
        .into_response());
    }

    Ok(Redirect::to("/"))
}
