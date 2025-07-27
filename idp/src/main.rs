mod oidc;
mod session;
mod totp;
mod users;

use std::{str::FromStr, time::Duration};

use askama::Template;
use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use color_eyre::Result;
use color_eyre::eyre::Context;
use serde::Deserialize;
use serde_json::json;
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
        .route("/logout", post(logout))
        .route("/signup", get(signup).post(signup_post))
        .route("/login", get(login).post(login_post))
        .route("/login-2fa", get(login_2fa).post(login_2fa_post))
        .route("/2fa", get(list_2fa))
        .route("/sessions", get(list_sessions))
        .route("/sessions/delete", post(delete_session))
        .route("/2fa/delete", post(delete_2fa))
        .route("/add-totp", get(add_totp).post(add_totp_post))
        .route("/users", get(users))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/oauth-clients", get(oauth_clients))
        .route(
            "/add-oauth-client",
            get(add_oauth_client).post(add_oauth_client_post),
        )
        .route("/connect/authorize", get(connect_authorize))
        .route("/connect/token", post(connect_token))
        .route("/jwks.json", get(jwks))
        .with_state(Db { pool });

    let addr = "0.0.0.0:2999";
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

async fn logout(
    State(db): State<Db>,

    jar: CookieJar,
    user: UserSession,
) -> Result<Response, Response> {
    let Some(user) = user.0 else {
        return Ok(Redirect::to("/").into_response());
    };

    session::delete_session(&db, user.user_id, user.session_public_id)
        .await
        .map_err(|err| {
            error!(?err, "Error deleting session for logout");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    Ok((jar.remove(SESSION_ID_COOKIE_NAME), Redirect::to("/")).into_response())
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

    // TODO: limit age of locked session

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

async fn openid_configuration() -> impl IntoResponse {
    Json(serde_json::json!({
        "issuer": "http://localhost:2999",
        "authorization_endpoint": "http://localhost:2999/connect/authorize",
        "token_endpoint": "http://localhost:2999/connect/token",
        "userinfo_endpoint": "http://localhost:2999/connect/userinfo",
        "jwks_uri": "http://localhost:2999/jwks.json",
        "response_types_supported": ["id_token"],
        "grant_types_supported": ["authorization_code"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
}

async fn oauth_clients(State(db): State<Db>) -> Result<impl IntoResponse, Response> {
    let clients = oidc::list_oauth_clients(&db).await.map_err(|err| {
        error!(?err, "Failed to list oauth clients");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    #[derive(askama::Template)]
    #[template(path = "oauth-clients.html")]
    struct OAuthClientsTemplate {
        clients: Vec<oidc::OAuthClient>,
    }

    Ok(Html(OAuthClientsTemplate { clients }.render().unwrap()))
}

#[derive(askama::Template)]
#[template(path = "add-oauth-client.html")]
struct AddOAuthClientTemplate {
    error: Option<String>,
}

async fn add_oauth_client() -> impl IntoResponse {
    Html(AddOAuthClientTemplate { error: None }.render().unwrap())
}

#[derive(Deserialize)]
struct AddOAuthClientForm {
    app_name: String,
    redirect_uri: String,
    client_type: String,
}

async fn add_oauth_client_post(
    State(db): State<Db>,
    Form(form): Form<AddOAuthClientForm>,
) -> Result<impl IntoResponse, Response> {
    if let Err(err) = url::Url::parse(&form.redirect_uri) {
        return Err(Html(
            AddOAuthClientTemplate {
                error: Some(format!("invalid redirect URI: {err}")),
            }
            .render()
            .unwrap(),
        )
        .into_response());
    }

    oidc::insert_oauth_client(&db, &form.app_name, &form.redirect_uri, &form.client_type)
        .await
        .map_err(|err| {
            error!(?err, "Failed to add oauth client");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    Ok(Redirect::to("/oauth-clients"))
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    client_id: String,
    scope: String,
    response_type: String,
    redirect_uri: Option<String>,
    state: Option<String>,
}

async fn connect_authorize(
    user: UserSession,
    Query(query): Query<AuthorizeQuery>,
    State(db): State<Db>,
) -> Result<impl IntoResponse, Response> {
    let Some(user) = user.0 else {
        return Err(Redirect::to("/login").into_response());
    };

    let clients = oidc::list_oauth_clients(&db).await.map_err(|err| {
        error!(?err, "Failed to add oauth client");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;
    let Some(client) = clients
        .iter()
        .find(|client| client.client_id == query.client_id)
    else {
        return Err("invalid client_id".into_response());
    };

    if query
        .redirect_uri
        .is_some_and(|redirect_uri| redirect_uri != client.redirect_uri)
    {
        return Err("invalid redirect_uri".into_response());
    }

    if query.response_type != "code" {
        return Err("unsupported response type, must be 'code'".into_response());
    }

    let mut redirect_uri = url::Url::parse(&client.redirect_uri).map_err(|err| {
        error!(?err, "invalid redirect URI");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let code = oidc::generate_string(32);
    oidc::insert_code(&db, &code, &query.client_id, user.user_id, &query.scope)
        .await
        .map_err(|err| {
            error!(?err, "Failed to insert oauth authorization code");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    redirect_uri.query_pairs_mut().append_pair("code", &code);

    if let Some(state) = query.state {
        redirect_uri.query_pairs_mut().append_pair("state", &state);
    }

    Ok(Redirect::to(redirect_uri.as_str()))
}

#[derive(Deserialize)]
struct ConnectTokenForm {
    grant_type: String,
    code: String,
}

async fn connect_token(
    headers: HeaderMap,
    State(db): State<Db>,
    Form(form): Form<ConnectTokenForm>,
) -> Result<impl IntoResponse, Response> {
    fn authorization(headers: HeaderMap) -> Option<(String, String)> {
        let auth = str::from_utf8(headers.get(header::AUTHORIZATION)?.as_bytes()).ok()?;
        let token = auth.strip_prefix("Basic ")?;
        let parts = base64::prelude::BASE64_STANDARD.decode(token).ok()?;
        let mut parts = str::from_utf8(&parts).ok()?.split(':');
        let username = parts.next()?;
        let password = parts.next()?;
        if !parts.next().is_none() {
            return None;
        }
        Some((username.to_owned(), password.to_owned()))
    }

    let Some(auth) = authorization(headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_client"
            })),
        )
            .into_response());
    };

    if form.grant_type != "authorization_code" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant"
            })),
        )
            .into_response());
    }

    let code = oidc::find_code(&db, &form.code, &auth.0, &auth.1)
        .await
        .map_err(|err| {
            error!(?err, "Error finding oauth code");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let Some(code) = code else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "unauthorized_client"
            })),
        )
            .into_response());
    };

    oidc::mark_code_as_used(&db, &form.code)
        .await
        .map_err(|err| {
            error!(?err, "Error finding oauth code");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let scopes = code.scope.split(' ').collect::<Vec<_>>();
    if !scopes.contains(&"openid") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_grant"
            })),
        )
            .into_response());
    }

    // TODO verify redirect_uri if present

    // fun https://datatracker.ietf.org/doc/html/rfc7519
    let id_token_headers = BASE64_URL_SAFE_NO_PAD.encode(
        serde_json::to_string(&json!({
            "typ": "JWT",
            "alg": "RS256",
            "kid": "1"
        }))
        .unwrap(),
    );

    let id_token_body = BASE64_URL_SAFE_NO_PAD.encode( serde_json::to_string(&json!({
        "iss": "http://localhost:2999",
        "sub": code.user_id.to_string(),
        "aud": auth.0.to_string(),
        "exp": jiff::Timestamp::now().checked_add(Duration::from_secs(3600)).unwrap().as_second(),
        "iat": jiff::Timestamp::now().as_second(),
    }))
    .unwrap());

    use rsa::signature::{RandomizedSigner, SignatureEncoding};

    let p = rsa::BigUint::from_bytes_be(&BASE64_URL_SAFE_NO_PAD.decode(RSA_KEY_P).unwrap());
    let q = rsa::BigUint::from_bytes_be(&BASE64_URL_SAFE_NO_PAD.decode(RSA_KEY_Q).unwrap());

    let key = rsa::RsaPrivateKey::from_p_q(p, q, rsa::BigUint::from(65537_u32)).unwrap();
    let key = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(key);

    let payload = format!("{id_token_headers}.{id_token_body}");

    let signature = key.sign_with_rng(&mut rand_core::OsRng, &payload.as_bytes());

    let id_token_signature = BASE64_URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let id_token = format!("{payload}.{id_token_signature}");

    dbg!(&id_token);

    Ok((
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(json!({
            "access_token": "",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
            "scope": scopes
        })),
    ))
}

const RSA_KEY_P: &str = "wyT2tVnlFA_mAD3SatHxaoD5OsE7kzxQb9rNx1PZ5GiK9fcyRE6xfS4pv_5RsvqHgwgZYNaydMytsg7Uq2gcQCA7gAyKD56ROw6nQCt2Tnv2US1Lu4s_DnUlQYdAaWwOYWCSOyrMH1TxtgCzveT9qO1PAknzyWJyb4wm9JMyzFdKh_Ck3nCO9_YhwmhYg3H1eT2cB-mdIG2ULc7yB8gvLccOqDea_C0LNur_iPTs9xwQnIOkD3GSKetWaHyXq2EnhFCoPStWZjUmItIrbEelcFOIIXTUWKk5eAQtOfmBjrEEimHktmVZNSppooD8zYq9cIxjyfjMfeneBDtGdK_xCQ";
const RSA_KEY_Q: &str = "1nsOGyOanwY5-JtAnf_m3wnzbAbY40bLB6DLQe3LqWb4Ow7b0XpSdEHJwV0_8jA1pNi3PouSDHSvj8G7Af9BncL2w9aTO1v6G_sHvHbP2U49RHrpRepBWrCWd2dV_CJdKJef4s2xURk44tPebZyPggvGo77qVWBal-MRkQcwnJHMgaht5QisP1LLSPjWswMkPQkuoIqqZlhFtgIkyz0hLqil1CbylU7i1ExXko8GT2fp8AG5iwdAJ6FrwyIuDTAgI2kx5tVpEdFfRDY7J2icbhvVVOFihkpjWUp-nVcp1K1ksaqU9_N3lu902L_lYusFMTxvqQ7yL5OYY4e3K-WRZw";

// https://datatracker.ietf.org/doc/html/rfc7517
fn rsa_key() -> serde_json::Value {
    json!({
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "1",
      "d": "BgjgM5QdqgFmL4DaDQuFW-cLpkUBsvxX2rr4-vy-d71puXN-x8T_NBfZ3oBcjpl2Aghc23ahD5gsiRBqka7BvP30NfHXEjMgBArgYowAM7Qp_e22yiBsAhU1F19ffhymu_1wAngRqHF9kPR8X3_noekffX5KwE660DkYM5l4S6O6TJfZdiynWJrM6PcZqIRRE7ughLEQpfStnDcgmtCgeoGESimnV-8WKD1PQAdJr4oj4hdFLQzXxygVKy1gilWdbMt8R-gUE6Vl22I0Bsw-LY71fG2Yw08_poNStuZ4ZRzLaGuYh5JjM4oUPWn7z-iJoUZmSfwq-zAKRhVNMGwwk79vhCSbd5pKKeCtApvztl7x8HY71M-UY5m4XyZ0aO4d9VkwzpOD9KbaDW4SIoeaYPLZFkVAVsthrh0fTblWV6w1Ko-h8M5IxDvdz8JSvkkxJlz-wucMe86RzeZ4dMOQEM2zv3To6Ru6nPXwzN5YGCvvGNUJGAPbrNDRAq4GVNKlIBPJUK0KkLHDzHuvsK-m30wOFmUlSpely-M9Rhq4wVBhg_o7zeeUCe9aNaeqTtwol7SO23n2qqzznoPUOQEIJg8h2lLW5gh-uNbRRfQh2oOvFsQVQZPZDtaxs7XhZYywxe3XiZ5wP4J3S8gyb9an6zvGsYAHKt7tg69LdrAv6JE",
      "n": "o36zvtfPixDY1T_Eg2TlzJwn7kpJ3iOlvFtn0FkM20PHlC8DM_A6iGtOdNwGPWH0uoJ5r03W9knh3S1cnFf9Apz3NJoxvmgojNjIYPrkxU3AgzJYPpE2Icg_Iqe5dqY9qQbg-3Uqfdih9x2qs02xPmnD9FX1ewYmn15WpDYsWpeKWi6SC91y9R15kpL02PJOG2DcKGHte25VZIJ3ysrnrGULgF1J7kQp1j87TMho266pj_GHmcV1XThw8mfk4JXUBMC47KvdQkyRR6cKlT9IeMPk18s2LKk3UsFflkvpGMi04l5Jx8vNZ_QfsewFtA1JG5_ce3HeRzmepoeYeF4U9ClDRKRslqOBPcx-aMB3gE6nwMA2JYt8xtCxjoptSfZAeyoOLd4s739tpxwjpiXzcuNOCvhYN_zOzdaMZCTJJ1E5UQpDdw8-9u3ZR7ZPlJFY6uVA6EJ6kOz4EKBPw2A_MWoRS0SjFokPGWfOaaccONNE8Gks2tWZtGxFXXW63JTS8T9LcZ-6mwan4XRhVGUUynBCLsv6wplVhH1kOkbIXDpyfpembOhdFQe9NuwZpdutIbi2DPFfYmrEr3xyGEteR69WGo7OyIGGL6His46xs5YBj_X3_aDltz-jYI11OdfQj2XmiBI8PIAzgYKULLPfrupgFaswsJzPVUK8vrpdE58",
      "e": "AQAB",
      "p": RSA_KEY_P,
      "q": RSA_KEY_Q,
      "dp": "PbJCDbQOKPmdzhW9oOgfW3zLTzgojbRT-glDZfGswfoLdRhiXBZFJz6hFIJjciKjFVpKK8O1SBguEk1-D3Mq-1s1dJaCT83iPLm1RyR2kvm-NowLlY_Ar-F5le4c_zealE7j7LDrODyy7sfqC--KAw6EHEUlPlZRt9KnvkuLk-9FMRV0Cp-rk9nNcplq4qP06BACdL33X3lFj_YNr0grIl381FJAPdo_4W0KvVIyWS4WUmWMSRWvEHHHL-G0Ugq1Y6_cgPpipo3HMNshv2ondAv0zh8Rw7Y85STs55dqzqJIvTeWB9SjD5wJKcd-Jb3nht3b7s8qV-TIvK3A6MN3gQ",
      "dq": "Gl1WBpAB2bpyNdUfxExInPIkMgtFbeqt2moxkhEhD9nQebIB42Yd7JyJqHNGAQdcEL9zBwUxFsbhLdKqojw2XKYynzApOQq9W-MnuEsCkbvEXD6fnjCFiBhc5qCVOUEgInVA-ig-u7FWBMv2c5LjMSExcb9uHsCRYkpPRnyTxStG8Ek7-QNv6PjMdFPiUG76bWZLjQB-ocYIC6-HxlPlWE7y03lWKHRh_abEvQdHx0sGvrH3lNd3U2fMT1hMQOLBkJjFwZJKMB6Ej2X7L4T0dbSGLMDn04ohXECD_-NPCQ2naw-E8FXFRZB51IsCL36kTMEZGLb1nlOOT-3G3maB0Q",
      "qi": "gakrrA_MsPcjAFsE_I9amgoTI4pLe3Da3WAA24iBMNBv6M0xZV7GGKv0pMvSfZzsQeQH4eqZwbSRjLeUz9dU4eW02k9RvfASImvyCyhstAj6oGtrqcKuPOR9n4Wci0tXbRawbXhDR7y6Kyj7LHEketqJGVciGmYgcZEC017LOR0lJhcb_WwgcFnqBa2qx6wYknI6EsTyaxjJzTm1bPusi8oe5RQ_-SqG36yfPBdjNLDm0XvNRXZkQC26MzESL4AU-dakUvFsUl7WG8lIevponmooNlR0KTVmCJE9fM5H8dap_CyrPfDtUxm75YBPuk5EvZNShyo6JdN7eltT-5JRCQ"
    })
}

async fn jwks() -> impl IntoResponse {
    // https://datatracker.ietf.org/doc/html/rfc7517

    let key = rsa_key();

    Json(json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "1",
            "n": key["n"],
            "e": key["e"]
        }],
    }))
}
