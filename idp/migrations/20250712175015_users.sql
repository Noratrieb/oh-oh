CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- ensure no IDs are reused
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
) STRICT;

CREATE INDEX users_username ON users(username);
