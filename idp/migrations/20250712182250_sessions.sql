CREATE TABLE IF NOT EXISTS sessions (
    session_public_id INTEGER NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    created INTEGER NOT NULL,
    user_agent TEXT NOT NULL,
    locked_2fa INTEGER NOT NULL, -- whether the session is currently locked and needs a 2FA code to unlock it

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) STRICT;

CREATE INDEX sessions_session_public_id ON sessions(session_public_id);
