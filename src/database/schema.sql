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
