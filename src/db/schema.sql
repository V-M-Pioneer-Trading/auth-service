CREATE TABLE IF NOT EXISTS credential (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    account_token         TEXT NOT NULL,
    agent_token           TEXT NOT NULL,
    agent_symbol          TEXT NOT NULL,
    faction               TEXT NOT NULL,
    email                 TEXT NOT NULL DEFAULT '',
    reset_date            TEXT NOT NULL DEFAULT '',
    next_predicted_reset  TEXT NOT NULL DEFAULT '',
    token_expired         INTEGER NOT NULL DEFAULT 0,
    updated_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS registration_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    event       TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT ''
);
