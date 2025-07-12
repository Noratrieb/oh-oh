CREATE TABLE IF NOT EXISTS sessions (
    session_public_id INTEGER NOT NULL PRIMARY KEY,
    session_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    created INTEGER NOT NULL,
    user_agent TEXT NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) STRICT;

CREATE INDEX sessions_session_public_id ON sessions(session_public_id);
