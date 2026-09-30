-- Эти две схемы подключены к users.db через ATTACH DATABASE.
-- SQLite не поддерживает внешние ключи между файлами: связи защищены
-- TEMP-триггерами из storage_links.sql в каждом соединении приложения.

CREATE TABLE IF NOT EXISTS documents_store.documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL CHECK(length(trim(title)) > 0 AND length(title) <= 500),
    content TEXT NOT NULL,
    original_name TEXT,
    owner_id INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK(revision >= 1),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS documents_store.idx_documents_owner
    ON documents(owner_id);

CREATE TABLE IF NOT EXISTS tables_store.converted_tables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL CHECK(length(trim(title)) > 0 AND length(title) <= 500),
    report_json TEXT NOT NULL CHECK(json_valid(report_json) AND json_type(report_json) = 'object'),
    owner_id INTEGER NOT NULL,
    direction_id INTEGER NOT NULL,
    secrecy_level_id INTEGER NOT NULL,
    source_document_id INTEGER,
    source_revision INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK((source_document_id IS NULL AND source_revision IS NULL)
       OR (source_document_id IS NOT NULL AND source_revision IS NOT NULL AND source_revision >= 1))
);
CREATE INDEX IF NOT EXISTS tables_store.idx_converted_tables_owner
    ON converted_tables(owner_id);
CREATE INDEX IF NOT EXISTS tables_store.idx_converted_tables_access
    ON converted_tables(direction_id, secrecy_level_id);
CREATE INDEX IF NOT EXISTS tables_store.idx_converted_tables_source
    ON converted_tables(source_document_id);
