CREATE TABLE IF NOT EXISTS used_totp (
    user_id INTEGER,
    time_step INTEGER,

    PRIMARY KEY (user_id, time_step),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) STRICT;

CREATE TABLE IF NOT EXISTS totp_devices (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    secret TEXT NOT NULL,
    created_time INTEGER NOT NULL,
    name TEXT NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) STRICT;

CREATE INDEX totp_devices_user_id ON totp_devices(user_id);
