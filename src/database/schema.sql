-- Направления деятельности
CREATE TABLE IF NOT EXISTS directions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

-- Уровни секретности
CREATE TABLE IF NOT EXISTS secrecy_levels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    level_order INTEGER NOT NULL
);

-- Пользователи
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    direction_id INTEGER NOT NULL,
    secrecy_level_id INTEGER NOT NULL,
    is_admin INTEGER DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    network_blocked INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (direction_id) REFERENCES directions(id),
    FOREIGN KEY (secrecy_level_id) REFERENCES secrecy_levels(id)
);

-- Метаданные файлов/папок
CREATE TABLE IF NOT EXISTS files_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL UNIQUE,
    direction_id INTEGER NOT NULL,
    secrecy_level_id INTEGER NOT NULL,
    owner_id INTEGER NOT NULL,
    is_directory INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (direction_id) REFERENCES directions(id),
    FOREIGN KEY (secrecy_level_id) REFERENCES secrecy_levels(id),
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- Сохранённые сессии (состояние рабочей среды)
CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    last_directory TEXT,
    window_state BLOB,
    open_files TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Логи аудита
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Индексы для оптимизации
CREATE INDEX IF NOT EXISTS idx_users_login ON users(login);
CREATE INDEX IF NOT EXISTS idx_files_metadata_path ON files_metadata(path);
CREATE INDEX IF NOT EXISTS idx_files_metadata_direction ON files_metadata(direction_id);
CREATE INDEX IF NOT EXISTS idx_files_metadata_secrecy ON files_metadata(secrecy_level_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- Счётчики сохраняются между перезапусками приложения.
CREATE TABLE IF NOT EXISTS login_attempts (
    login TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS live_sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    started_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    ended_at REAL,
    end_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_live_sessions_user ON live_sessions(user_id, ended_at);
CREATE TABLE IF NOT EXISTS emergency_credentials (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    login TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    batch_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS emergency_state (
    id INTEGER PRIMARY KEY CHECK(id=1),
    batch_id TEXT NOT NULL,
    prepared_at REAL NOT NULL,
    consumed_at REAL
);
CREATE TABLE IF NOT EXISTS emergency_reports (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    actor_id INTEGER NOT NULL REFERENCES users(id),
    report_json TEXT NOT NULL
);

-- Administrative challenge/response monitor (shared database).
CREATE TABLE IF NOT EXISTS connectivity_schedule (
    id INTEGER PRIMARY KEY CHECK(id=1), next_poll REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS connectivity_challenges (
    session_id TEXT PRIMARY KEY REFERENCES live_sessions(id),
    nonce TEXT NOT NULL UNIQUE, issued_at REAL NOT NULL, deadline REAL NOT NULL,
    answered_at REAL, resolved_at REAL
);

-- Ревизия учётных данных изменяется в той же транзакции, что и аккаунт.
-- Локальная ревизия отличается от последней полученной ревизии сервера.
CREATE TABLE IF NOT EXISTS account_sync_state (
    id INTEGER PRIMARY KEY CHECK(id=1),
    revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0)
);
INSERT OR IGNORE INTO account_sync_state(id,revision) VALUES (1,0);
CREATE TABLE IF NOT EXISTS lan_sync_state (
    id INTEGER PRIMARY KEY CHECK(id=1),
    revision INTEGER NOT NULL DEFAULT -1 CHECK(revision >= -1),
    server_id TEXT
);
INSERT OR IGNORE INTO lan_sync_state(id,revision) VALUES (1,-1);
CREATE TABLE IF NOT EXISTS server_identity (
    id INTEGER PRIMARY KEY CHECK(id=1),
    server_id TEXT NOT NULL UNIQUE
);

-- Только настоящий heartbeat по сети обновляет присутствие LAN-клиента.
CREATE TABLE IF NOT EXISTS lan_presence (
    session_id TEXT PRIMARY KEY REFERENCES live_sessions(id),
    address TEXT,
    client_name TEXT,
    last_heartbeat REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lan_presence_heartbeat ON lan_presence(last_heartbeat);
