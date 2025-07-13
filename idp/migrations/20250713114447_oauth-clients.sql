CREATE TABLE oauth_clients (
    app_name TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL PRIMARY KEY,
    client_secret TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    client_type TEXT NOT NULL
) STRICT;

INSERT INTO oauth_clients (app_name, client_id, client_secret, redirect_uri, client_type)
VALUES ('example', 'EUWCM5WHWTWR43AK', 'VC3PLLVMGSVKL4YE3WICL4URJQUC443I', 'http://localhost:3333/callback', 'confidential');

CREATE TABLE oauth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    created_time_ms INTEGER NOT NULL,
    user_id INTEGER NOT NULl,
    used INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY(client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
) STRICT;
